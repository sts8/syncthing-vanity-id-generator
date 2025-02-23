import multiprocessing as mp
import time


def benchmark_iterations_per_second(worker_function) -> int:
    count = 0
    start_time = time.time()

    while time.time() - start_time < 3:
        worker_function()
        count += 1

    return round(count / 3.0)


def worker_wrapper(worker_function, batch_size: int, counter: mp.Value):
    while True:
        for _ in range(batch_size):
            worker_function()

        with counter.get_lock():
            counter.value += batch_size


def run_parallel(worker_function, batch_size: int = 500, n_procs: int = mp.cpu_count()):
    print(f"batch_size: {batch_size}, n_procs: {n_procs}")

    counter = mp.Value('i', 0)
    start_time = time.time()
    processes = []

    for _ in range(n_procs):
        process = mp.Process(target=worker_wrapper, args=(worker_function, batch_size, counter))
        processes.append(process)
        process.start()

    try:
        while True:
            time.sleep(3)
            time_elapsed = time.time() - start_time
            print(f"Total: {counter.value}, {round(counter.value / time_elapsed)}/s")

    except KeyboardInterrupt:
        print("Terminating processes...")
        for process in processes:
            process.terminate()
    finally:
        for process in processes:
            process.join()
