#include <metal_stdlib>
using namespace metal;

struct RemoteVertex {
    packed_float2 position;
    packed_float2 textureCoordinate;
};

struct RemoteRasterData {
    float4 position [[position]];
    float2 textureCoordinate;
};

vertex RemoteRasterData remoteVertex(
    uint vertexID [[vertex_id]],
    const device RemoteVertex *vertices [[buffer(0)]])
{
    RemoteRasterData output;
    output.position = float4(vertices[vertexID].position, 0.0, 1.0);
    output.textureCoordinate = vertices[vertexID].textureCoordinate;
    return output;
}

fragment float4 remoteNV12Fragment(
    RemoteRasterData input [[stage_in]],
    texture2d<float, access::sample> lumaTexture [[texture(0)]],
    texture2d<float, access::sample> chromaTexture [[texture(1)]])
{
    constexpr sampler videoSampler(coord::normalized, address::clamp_to_edge, filter::linear);
    const float y = lumaTexture.sample(videoSampler, input.textureCoordinate).r;
    const float2 cbcr = chromaTexture.sample(videoSampler, input.textureCoordinate).rg - float2(0.5);
    const float adjustedY = max(0.0, (y - (16.0 / 255.0)) * 1.164383);
    const float3 rgb = float3(
        adjustedY + 1.596027 * cbcr.y,
        adjustedY - 0.391762 * cbcr.x - 0.812968 * cbcr.y,
        adjustedY + 2.017232 * cbcr.x
    );
    return float4(saturate(rgb), 1.0);
}
