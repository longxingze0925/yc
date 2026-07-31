import AVFoundation
import CoreMedia
import CoreVideo
import Foundation
import VideoToolbox

public struct DecodedFrameMetadata: Equatable, Sendable {
    public let presentationTimeMillis: Int64
    public let frameID: UInt64

    public init(presentationTimeMillis: Int64, frameID: UInt64) {
        self.presentationTimeMillis = presentationTimeMillis
        self.frameID = frameID
    }
}

public enum H264DecoderError: LocalizedError, Equatable {
    case missingParameterSets
    case invalidParameterSets(OSStatus)
    case sessionCreationFailed(OSStatus)
    case invalidAccessUnit
    case sampleCreationFailed(OSStatus)
    case decodeFailed(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .missingParameterSets:
            return "H.264 关键帧缺少 SPS/PPS"
        case let .invalidParameterSets(status):
            return "H.264 参数集无效（\(status)）"
        case let .sessionCreationFailed(status):
            return "VideoToolbox 解码会话创建失败（\(status)）"
        case .invalidAccessUnit:
            return "H.264 Annex-B 访问单元无效"
        case let .sampleCreationFailed(status):
            return "H.264 样本创建失败（\(status)）"
        case let .decodeFailed(status):
            return "VideoToolbox 解码失败（\(status)）"
        }
    }
}

public enum AnnexBParser {
    public static func nalUnits(from data: Data) -> [Data] {
        let bytes = [UInt8](data)
        guard let first = startCode(in: bytes, from: 0) else { return [] }

        var units: [Data] = []
        var payloadStart = first.index + first.length
        while payloadStart < bytes.count {
            if let next = startCode(in: bytes, from: payloadStart) {
                if next.index > payloadStart {
                    units.append(Data(bytes[payloadStart..<next.index]))
                }
                payloadStart = next.index + next.length
            } else {
                if payloadStart < bytes.count {
                    units.append(Data(bytes[payloadStart..<bytes.count]))
                }
                break
            }
        }
        return units.filter { !$0.isEmpty }
    }

    private static func startCode(in bytes: [UInt8], from start: Int) -> (index: Int, length: Int)? {
        guard bytes.count >= 3, start <= bytes.count - 3 else { return nil }
        var index = max(0, start)
        while index <= bytes.count - 3 {
            if bytes[index] == 0, bytes[index + 1] == 0 {
                if bytes[index + 2] == 1 {
                    return (index, 3)
                }
                if index + 3 < bytes.count, bytes[index + 2] == 0, bytes[index + 3] == 1 {
                    return (index, 4)
                }
            }
            index += 1
        }
        return nil
    }
}

public final class H264Decoder: @unchecked Sendable {
    public typealias FrameHandler = @Sendable (CVPixelBuffer, DecodedFrameMetadata) -> Void
    public typealias FailureHandler = @Sendable (H264DecoderError, UInt64?) -> Void

    private final class FrameContext {
        let decoder: H264Decoder
        let metadata: DecodedFrameMetadata

        init(decoder: H264Decoder, metadata: DecodedFrameMetadata) {
            self.decoder = decoder
            self.metadata = metadata
        }
    }

    private let queue = DispatchQueue(label: "com.remotecontroller.ios.h264-decoder")
    private let queueKey = DispatchSpecificKey<UInt8>()
    private var decompressionSession: VTDecompressionSession?
    private var formatDescription: CMVideoFormatDescription?
    private var sequenceParameterSet: Data?
    private var pictureParameterSet: Data?
    private var frameHandler: FrameHandler?
    private var failureHandler: FailureHandler?

    public init() {
        queue.setSpecific(key: queueKey, value: 1)
    }

    deinit {
        invalidate()
    }

    public func setHandlers(onFrame: FrameHandler?, onFailure: FailureHandler?) {
        queue.async { [weak self] in
            self?.frameHandler = onFrame
            self?.failureHandler = onFailure
        }
    }

    public func decode(_ accessUnit: H264AccessUnit) {
        queue.async { [weak self] in
            self?.decodeOnQueue(accessUnit)
        }
    }

    public func flush() {
        performSynchronously {
            guard let decompressionSession else { return }
            VTDecompressionSessionFinishDelayedFrames(decompressionSession)
            VTDecompressionSessionWaitForAsynchronousFrames(decompressionSession)
        }
    }

    public func invalidate() {
        performSynchronously {
            invalidateOnQueue()
            sequenceParameterSet = nil
            pictureParameterSet = nil
        }
    }

    private func decodeOnQueue(_ accessUnit: H264AccessUnit) {
        let nalUnits = AnnexBParser.nalUnits(from: accessUnit.data)
        guard !nalUnits.isEmpty else {
            failureHandler?(.invalidAccessUnit, accessUnit.frameID)
            return
        }

        let newSPS = nalUnits.last { nalType($0) == 7 }
        let newPPS = nalUnits.last { nalType($0) == 8 }
        if let newSPS { sequenceParameterSet = newSPS }
        if let newPPS { pictureParameterSet = newPPS }

        if newSPS != nil || newPPS != nil || decompressionSession == nil {
            do {
                try rebuildSessionIfPossible()
            } catch let error as H264DecoderError {
                failureHandler?(error, accessUnit.frameID)
                return
            } catch {
                failureHandler?(.invalidAccessUnit, accessUnit.frameID)
                return
            }
        }

        guard let decompressionSession, let formatDescription else {
            failureHandler?(.missingParameterSets, accessUnit.frameID)
            return
        }

        let frameNALUnits = nalUnits.filter { nalType($0) != 7 && nalType($0) != 8 }
        guard !frameNALUnits.isEmpty else { return }

        do {
            let sampleBuffer = try makeSampleBuffer(
                nalUnits: frameNALUnits,
                formatDescription: formatDescription,
                presentationTimeMillis: accessUnit.presentationTimeMillis,
                isKeyframe: accessUnit.isKeyframe
            )
            let metadata = DecodedFrameMetadata(
                presentationTimeMillis: accessUnit.presentationTimeMillis,
                frameID: accessUnit.frameID
            )
            let context = Unmanaged.passRetained(FrameContext(decoder: self, metadata: metadata))
            let status = VTDecompressionSessionDecodeFrame(
                decompressionSession,
                sampleBuffer: sampleBuffer,
                flags: [.enableAsynchronousDecompression],
                frameRefcon: context.toOpaque(),
                infoFlagsOut: nil
            )
            if status != noErr {
                context.release()
                failureHandler?(.decodeFailed(status), accessUnit.frameID)
            }
        } catch let error as H264DecoderError {
            failureHandler?(error, accessUnit.frameID)
        } catch {
            failureHandler?(.invalidAccessUnit, accessUnit.frameID)
        }
    }

    private func rebuildSessionIfPossible() throws {
        guard let sequenceParameterSet, let pictureParameterSet else {
            throw H264DecoderError.missingParameterSets
        }
        invalidateOnQueue()

        var description: CMFormatDescription?
        let descriptionStatus = sequenceParameterSet.withUnsafeBytes { spsBuffer in
            pictureParameterSet.withUnsafeBytes { ppsBuffer in
                guard let sps = spsBuffer.bindMemory(to: UInt8.self).baseAddress,
                      let pps = ppsBuffer.bindMemory(to: UInt8.self).baseAddress else {
                    return kCMFormatDescriptionError_InvalidParameter
                }
                let pointers = [sps, pps]
                let sizes = [sequenceParameterSet.count, pictureParameterSet.count]
                return pointers.withUnsafeBufferPointer { pointerBuffer in
                    sizes.withUnsafeBufferPointer { sizeBuffer in
                        CMVideoFormatDescriptionCreateFromH264ParameterSets(
                            allocator: kCFAllocatorDefault,
                            parameterSetCount: 2,
                            parameterSetPointers: pointerBuffer.baseAddress!,
                            parameterSetSizes: sizeBuffer.baseAddress!,
                            nalUnitHeaderLength: 4,
                            formatDescriptionOut: &description
                        )
                    }
                }
            }
        }
        guard descriptionStatus == noErr, let videoDescription = description as? CMVideoFormatDescription else {
            throw H264DecoderError.invalidParameterSets(descriptionStatus)
        }

        let pixelAttributes: [CFString: Any] = [
            kCVPixelBufferPixelFormatTypeKey: kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
            kCVPixelBufferMetalCompatibilityKey: true,
            kCVPixelBufferIOSurfacePropertiesKey: [:] as CFDictionary
        ]
        var callback = VTDecompressionOutputCallbackRecord(
            decompressionOutputCallback: Self.outputCallback,
            decompressionOutputRefCon: nil
        )
        var newSession: VTDecompressionSession?
        let sessionStatus = VTDecompressionSessionCreate(
            allocator: kCFAllocatorDefault,
            formatDescription: videoDescription,
            decoderSpecification: nil,
            imageBufferAttributes: pixelAttributes as CFDictionary,
            outputCallback: &callback,
            decompressionSessionOut: &newSession
        )
        guard sessionStatus == noErr, let newSession else {
            throw H264DecoderError.sessionCreationFailed(sessionStatus)
        }
        formatDescription = videoDescription
        decompressionSession = newSession
        VTSessionSetProperty(
            newSession,
            key: kVTDecompressionPropertyKey_RealTime,
            value: kCFBooleanTrue
        )
    }

    private func makeSampleBuffer(
        nalUnits: [Data],
        formatDescription: CMVideoFormatDescription,
        presentationTimeMillis: Int64,
        isKeyframe: Bool
    ) throws -> CMSampleBuffer {
        var avcc = Data()
        for nalUnit in nalUnits {
            guard nalUnit.count <= Int(UInt32.max) else { throw H264DecoderError.invalidAccessUnit }
            var size = UInt32(nalUnit.count).bigEndian
            avcc.append(Data(bytes: &size, count: MemoryLayout<UInt32>.size))
            avcc.append(nalUnit)
        }

        var blockBuffer: CMBlockBuffer?
        var status = CMBlockBufferCreateWithMemoryBlock(
            allocator: kCFAllocatorDefault,
            memoryBlock: nil,
            blockLength: avcc.count,
            blockAllocator: kCFAllocatorDefault,
            customBlockSource: nil,
            offsetToData: 0,
            dataLength: avcc.count,
            flags: 0,
            blockBufferOut: &blockBuffer
        )
        guard status == kCMBlockBufferNoErr, let blockBuffer else {
            throw H264DecoderError.sampleCreationFailed(status)
        }
        status = avcc.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return kCMBlockBufferBadLengthParameterErr }
            return CMBlockBufferReplaceDataBytes(
                with: baseAddress,
                blockBuffer: blockBuffer,
                offsetIntoDestination: 0,
                dataLength: avcc.count
            )
        }
        guard status == kCMBlockBufferNoErr else {
            throw H264DecoderError.sampleCreationFailed(status)
        }

        var timing = CMSampleTimingInfo(
            duration: .invalid,
            presentationTimeStamp: CMTime(value: presentationTimeMillis, timescale: 1_000),
            decodeTimeStamp: .invalid
        )
        var sampleSize = avcc.count
        var sampleBuffer: CMSampleBuffer?
        status = CMSampleBufferCreateReady(
            allocator: kCFAllocatorDefault,
            dataBuffer: blockBuffer,
            formatDescription: formatDescription,
            sampleCount: 1,
            sampleTimingEntryCount: 1,
            sampleTimingArray: &timing,
            sampleSizeEntryCount: 1,
            sampleSizeArray: &sampleSize,
            sampleBufferOut: &sampleBuffer
        )
        guard status == noErr, let sampleBuffer else {
            throw H264DecoderError.sampleCreationFailed(status)
        }
        if !isKeyframe {
            CMSetAttachment(
                sampleBuffer,
                key: kCMSampleAttachmentKey_NotSync,
                value: kCFBooleanTrue,
                attachmentMode: kCMAttachmentMode_ShouldNotPropagate
            )
        }
        return sampleBuffer
    }

    private func invalidateOnQueue() {
        if let decompressionSession {
            VTDecompressionSessionFinishDelayedFrames(decompressionSession)
            VTDecompressionSessionWaitForAsynchronousFrames(decompressionSession)
            VTDecompressionSessionInvalidate(decompressionSession)
        }
        decompressionSession = nil
        formatDescription = nil
    }

    private func performSynchronously(_ operation: () -> Void) {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            operation()
        } else {
            queue.sync(execute: operation)
        }
    }

    private func nalType(_ data: Data) -> UInt8 {
        data.first.map { $0 & 0x1F } ?? 0
    }

    private func deliver(
        status: OSStatus,
        imageBuffer: CVImageBuffer?,
        metadata: DecodedFrameMetadata
    ) {
        guard status == noErr, let pixelBuffer = imageBuffer else {
            failureHandler?(.decodeFailed(status), metadata.frameID)
            return
        }
        frameHandler?(pixelBuffer, metadata)
    }

    private static let outputCallback: VTDecompressionOutputCallback = {
        _, sourceFrameRefCon, status, _, imageBuffer, _, _ in
        guard let sourceFrameRefCon else { return }
        let context = Unmanaged<FrameContext>.fromOpaque(sourceFrameRefCon).takeRetainedValue()
        context.decoder.queue.async {
            context.decoder.deliver(
                status: status,
                imageBuffer: imageBuffer,
                metadata: context.metadata
            )
        }
    }
}

public protocol RemoteH264Decoding: AnyObject, Sendable {
    func setHandlers(
        onFrame: H264Decoder.FrameHandler?,
        onFailure: H264Decoder.FailureHandler?
    )
    func decode(_ accessUnit: H264AccessUnit)
    func invalidate()
}

extension H264Decoder: RemoteH264Decoding {}
