//
// Created by 1877365685 on 2025/10/24.
//

// replay.h: 防重放攻击过滤器
// 实现 RFC 6479 指定的高效滑动窗口算法，用于检测重放数据包

#ifndef FVPN_REPLAY_H
#define FVPN_REPLAY_H

#include <cstdint> // 用于 uint64_t
#include <array>   // 用于 std::array

namespace fvpn::replay {

constexpr size_t blockBitLog = 6;                 // 块位数（2^6 = 64 位）
constexpr size_t blockBits = 1ULL << blockBitLog; // 每个块的位数
constexpr size_t ringBlocks = 1ULL << 7;          // 环形缓冲区块数
constexpr size_t windowSize = (ringBlocks - 1) * blockBits; // 滑动窗口大小
constexpr size_t blockMask = ringBlocks - 1;       // 块索引掩码
constexpr size_t bitMask = blockBits - 1;         // 位索引掩码

// Filter: 防重放过滤器，维护滑动窗口以检测重复计数器
class Filter {
public:
    Filter() : last_(0) { ring_.fill(0); } // 初始化为空状态

    // Reset: 重置过滤器为空状态
    void Reset();

    // ValidateCounter: 检查计数器是否有效（在窗口内且未重复）
    // 参数: counter - 数据包计数器, limit - 最大允许计数器
    // 返回: 是否接受该计数器
    bool ValidateCounter(uint64_t counter, uint64_t limit);

private:
    using block = uint64_t;                       // 块类型（64 位）
    uint64_t last_;                               // 最新计数器
    std::array<block, ringBlocks> ring_;          // 环形缓冲区，记录位状态
};

} // namespace fvpn::replay

#endif // FVPN_REPLAY_H
