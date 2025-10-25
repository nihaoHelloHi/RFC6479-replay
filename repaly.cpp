//
// Created by 1877365685 on 2025/10/24.
//

// replay.cpp: 防重放攻击过滤器实现，对应原 replay.go
// 实现 RFC 6479 滑动窗口算法，检测重放数据包

#include "replay.h"

namespace fvpn::replay {

// Reset: 重置过滤器状态
// 清零 last_ 和 ring_ 数组
void Filter::Reset() {
    last_ = 0;
    ring_.fill(0);
}

// ValidateCounter: 检查计数器是否有效
// 参数: counter - 数据包计数器, limit - 最大允许计数器
// counter-->[block_idx 58bits][block_num 6bits]
// 返回: true 表示接受（新计数器或窗口内未设置），false 表示拒绝（超限或重放）
bool Filter::ValidateCounter(uint64_t counter, uint64_t limit) {
    // 检查是否超过限制
    if (counter >= limit) {
        return false;
    }

    // 计算当前计数器的块索引
    uint64_t indexBlock = counter >> blockBitLog;

    // 如果计数器大于最新值，前移窗口
    if (counter > last_) {
        uint64_t current = last_ >> blockBitLog;
        uint64_t diff = indexBlock - current;
        if (diff > ringBlocks) {
            diff = ringBlocks; // 限制清零范围
        }
        for (uint64_t i = current + 1; i <= current + diff; ++i) {
            ring_[i & blockMask] = 0; // 清零窗口内的块
        }
        last_ = counter;
    } else if (last_ - counter > windowSize) {
        // 计数器落后窗口太远，拒绝
        return false;
    }

    // 检查并设置位
    indexBlock &= blockMask;
    uint64_t indexBit = counter & bitMask;
    block old = ring_[indexBlock];
    block new_val = old | (1ULL << indexBit);
    ring_[indexBlock] = new_val;

    // 如果位未改变（已设置），表示重放
    return old != new_val;
}

} // namespace fvpn::replay