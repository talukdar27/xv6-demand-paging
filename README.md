# Demand Paging Implementation for xv6

A full implementation of demand paging with FIFO page replacement and swap file management for the xv6 operating system.

## Overview

This project extends xv6 with a complete virtual memory subsystem that includes on-demand page loading, page replacement, and disk-based swapping. Pages are allocated lazily on first access rather than being pre-allocated during `exec()` or `sbrk()` calls.

## Features

### 🧠 Demand Paging

- **Lazy Allocation**: Pages are loaded on first access — not preallocated at `exec` or `sbrk`
- **Page Fault Handling**:
  - Text/Data → Loaded from executable on demand
  - Heap/Stack → Zero-filled page allocation
  - Invalid accesses → Process termination with log entry
- **Complete Logging**: Every action (ALLOC, LOADEXEC, RESIDENT, etc.) is logged with `[pid X]`

### 🔄 FIFO Page Replacement

- **Memory-Pressure Triggered**: Only activates when system memory is full (`kalloc()` fails)
- **Per-Process Management**: Each process manages its own resident set independently
- **FIFO Algorithm**: Oldest page (lowest sequence number) evicted first
- **Sequence Wraparound**: Properly handles sequence number overflow
- **Detailed Logging**: Includes MEMFULL, VICTIM, EVICT, DISCARD, and SWAPOUT events

### 💾 Swapping

- **Process-Specific Swap Files**: Each process uses `/pgswpXXXXX` (PID-based naming)
- **Swap Capacity**: Up to 1024 pages (4MB) per process
- **Smart Eviction**:
  - Clean pages are discarded (no write needed)
  - Dirty pages are written to swap file
- **Swap-In Support**: Swapped pages are reloaded with SWAPIN and sequence update
- **Safe Termination**: Handles swap-full conditions gracefully
- **Cleanup on Exit**: Logs `SWAPCLEANUP freed_slots=K` when process terminates

### 📊 System Call: `memstat()`

Provides detailed per-process memory statistics:

- Resident, swapped, and unmapped pages
- Dirty flag status
- Sequence numbers
- Swap slot assignments
- Enables introspection for testing and debugging

## Logging Format

Sample output from the system:

```
[pid 3] ALLOC va=0x1000 pa=0xA000
[pid 3] LOADEXEC va=0x2000 pa=0xB000
[pid 3] MEMFULL
[pid 3] VICTIM va=0x1000 seq=1
[pid 3] EVICT va=0x1000 dirty=1
[pid 3] SWAPOUT va=0x1000 slot=0
[pid 3] SWAPIN va=0x1000 slot=0 seq=42
[pid 3] SWAPCLEANUP freed_slots=5
```

## Implementation Details

- **Page Size**: 4096 bytes
- **FIFO Tracking**: Per-process basis
- **Dynamic Slot Management**: Swap slots tracked and freed dynamically
- **Comprehensive Logging**: All events logged using `cprintf()`
- **Process Isolation**: No process can evict or access another process's pages

## Key Files

- `exec.c` - Process execution and program loading
- `proc.c` - Process management
- `kalloc.c` - Physical memory allocation
- `fs.c` - File system operations for swap file

## Running the Project

```bash
make qemu
```
