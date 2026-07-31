import Foundation

struct NativeVideoPacketGroupAssembler {
    private let maximumIncompleteGroups: Int
    private var groups: [UInt64: [UInt32: Data]] = [:]

    init(maximumIncompleteGroups: Int = 8) {
        self.maximumIncompleteGroups = max(1, maximumIncompleteGroups)
    }

    var incompleteGroupCount: Int { groups.count }

    mutating func insert(
        groupID: UInt64,
        index: UInt32,
        count: UInt32,
        packet: Data
    ) -> (info: Data, data: Data)? {
        guard count == 2, index < 2 else { return nil }
        if groups[groupID] == nil,
           groups.count >= maximumIncompleteGroups,
           let oldest = groups.keys.min() {
            groups.removeValue(forKey: oldest)
        }
        var group = groups[groupID] ?? [:]
        group[index] = packet
        guard let info = group[0], let data = group[1] else {
            groups[groupID] = group
            return nil
        }
        groups.removeValue(forKey: groupID)
        return (info, data)
    }
}
