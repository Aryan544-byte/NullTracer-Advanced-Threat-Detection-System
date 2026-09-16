"""
stress_test.py — NullTracer High-Load Process Spawner & Unload Stability Test
=============================================================================
Spawns 1,000 processes rapidly to measure kernel driver overhead (ProcessCreate
notify routine execution time) compared to the baseline OS overhead.
"""

import sys
import time
import subprocess
from rich.console import Console

console = Console(force_terminal=True, highlight=False)

def run_stress_test(num_processes=1000):
    console.print(f"[bold cyan]Spawning {num_processes} processes sequentially...[/bold cyan]")
    
    start_time = time.perf_counter()
    
    for i in range(num_processes):
        # cmd.exe /c exit is very lightweight
        subprocess.run(["cmd.exe", "/c", "exit"], capture_output=False, shell=False)
        
    end_time = time.perf_counter()
    elapsed = end_time - start_time
    
    avg_ms = (elapsed / num_processes) * 1000.0
    
    console.print(f"[bold green]Complete![/bold green] Total time: [bold yellow]{elapsed:.4f}s[/bold yellow]")
    console.print(f"Average time per process creation: [bold yellow]{avg_ms:.4f} ms[/bold yellow]")
    
if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_stress_test(int(sys.argv[1]))
    else:
        run_stress_test(1000)
