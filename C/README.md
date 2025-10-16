# Bakery Synchronization Problem

LLM Compilation
https://chatgpt.com/share/68f09d86-d9ac-8002-9804-e2a3261285dc


## Overview
This program simulates a bakery with limited resources using **multithreading** and **synchronization primitives** (semaphores, mutexes, condition variables).

## Problem Description
- **Bakery Capacity**: 25 customers maximum
- **Sofa Seats**: 4 seats (first-come-first-served)
- **Chefs**: 4 chefs handle baking and payment
- **Cash Register**: 1 register (mutual exclusion)

## Customer Flow
1. **Enter** bakery (if not full)
2. **Sit** on sofa (or stand and wait)
3. **Request** cake from chef
4. **Wait** for chef to bake
5. **Pay** at cash register
6. **Leave** bakery

## Synchronization Mechanisms
- **Semaphores**:
  - `capacity_sem` - Limits total customers (25)
  - `sofa_sem` - Limits sofa seats (4)
  - `cash_register` - Ensures one payment at a time
- **Mutex + Condition Variable**: Queue management
- **Per-customer semaphores**: Coordinate customer-chef interactions

## How to Compile

```bash
cd /home/user/Desktop/SEMESTER5/mini-project-2-talukdar27/C
gcc -o threading threading.c -pthread
```

## How to Run

### Method 1: Interactive Input (CLI)
```bash
./threading
```

Then enter customer arrivals:
```
Enter customer arrivals (format: timestamp Customer id)
Press Ctrl+D when done:
0 Customer 1
2 Customer 2
5 Customer 3
10 Customer 4
<Ctrl+D>
```

### Method 2: Pipe from File
```bash
cat input.txt | ./threading
```

### Method 3: Redirect from File
```bash
./threading < input.txt
```

## Input Format
Each line: `timestamp Customer id`

Example:
```
0 Customer 1
2 Customer 2
5 Customer 3
```

- `timestamp`: Arrival time in seconds (from simulation start)
- `id`: Unique customer identifier

## Sample Output

```
Input complete. 4 customers entered.
Starting simulation...

0 Simulation starting.
0 Customer 1 enters
0 Customer 1 sits
1 Customer 1 requests cake
2 Customer 2 enters
2 Customer 2 sits
2 Chef 1 starts baking for Customer 1
3 Customer 1 pays
3 Chef 2 accepts payment from Customer 1
5 Customer 1 leaves
5 Customer 3 enters
...
```

## Key Features
- **Non-blocking entry**: Customers rejected if bakery full
- **Standing queue**: Customers wait for sofa seats
- **Priority handling**: Chefs prioritize payment over baking
- **Resource cleanup**: Proper memory management and thread detachment
- **Two-phase execution**:
  1. Collect all input (until EOF)
  2. Start simulation with collected data

## Timing Constants
- `CUSTOMER_ACTION_SEC = 1`: Customer action delay
- `CHEF_ACTION_SEC = 2`: Chef action delay
- Simulation runs for 60 seconds after input

## Notes
- Press **Ctrl+D** to signal end of input and start simulation
- All times in output are relative to simulation start (not real time)
- Chefs run continuously in background threads
- Customers automatically cleaned up after leaving

## Troubleshooting

### Compile Error
```bash
# Install pthread library
sudo apt-get install build-essential

# Try explicit flags
gcc -o threading threading.c -lpthread -D_GNU_SOURCE
```

### Runtime Issues
- Ensure valid input format (`timestamp Customer id`)
- Check that timestamps are non-negative integers
- Press Ctrl+D after all inputs to start simulation