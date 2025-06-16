# PIN_detection

## Subject

*P11. PIN Detection. (several groups, 1-3 students each).*

The recent paper "Evasion and Countermeasures Techniques to Detect Dynamic Binary Instrumentation Frameworks" discusses 26 classes of evasion techniques to detect the presence of a dynamic instrumentation framework. Sadly, the authors also notice that PoC are only available for nine of them. The goal of this project is to make a Linux binary suite that tests sequentially different techniques to detect the presence of Intel PIN. Start by aggregating the nine existing PoC and then try to implement some of the other techniques described in the paper.

The different techniques are as follows:

1. Code Cache Fingerprints
2. IP in Unexpected Memory Regions
3. Incorrect Handling of Self-Modifying Code (SMC)
4. Memory Region Permission Mismatches
5. Process Hierarchy
6. Incorrect Emulation of Supported Assembly Instructions
7. System Library Hooks
8. Excessive Number of Full Access Memory Pages
9. Performance Degradation

This project was very enjoyable however, more time would have been welcome as in the current state, 6/9 evasion techniques work. 2 `IP in Unexpected Memory Regions` has trouble detecting when it is not in the expected cache. 3 `Incorrect Handling of Self-Modifying Code (SMC)` I'm not entirely sure how the self-modfying code is supposed to be altered incorrectly (I spent by far the most time on this, downgrading PIN, looking into valgrind, downgrading valgrind and its dependencies and even starting writing my own basic DBI to understand better where it might come from). Finally, I could never get close to  making 6 `Incorrect Emulation of Supported Assembly Instructions` work as I wasn't sure what kind of instrcutions could be ran on a modern computer but not in PIN, especially considering my CPU is an Intel one.
Overall, a pretty fun experience, especially with the malware engineer mindeset (what code can I write to infect as many machines as possible?) and will definitely try to work on this more once the exam session is done.
Because of the strict deadline, AI has been used way too much for my comfort but it will get soon fixed.

---

## Quickstart

1. **Configure Intel PIN path:**
   - Edit `pin.conf` and set the `PIN` variable to your Intel PIN installation path, or set the `PIN` environment variable.
2. **Build all techniques:**
   - `./compile_all.sh`
3. **Run all checks:**
   - `./run_all_evasions.sh`
   - Or use the interactive `quickstart.sh` (see below).

## Configuring PIN

- The path to Intel PIN is read from `pin.conf` (edit this file to set your path).
- Alternatively, set the `PIN` environment variable before running scripts:

  ```bash
  export PIN=/path/to/pin
  ```

- If neither is set, scripts use a default path (edit `pin.conf` to change it).
- All scripts will print a clear error if PIN is not found.

## Help and Usage

All main scripts support `-h` or `--help` for usage instructions:

```bash
./run_all_evasions.sh -h
./compile_all.sh --help
```

## Makefile and Quickstart

- A top-level `Makefile` is provided for convenience:
  - `make all` – build all binaries
  - `make run` – run all checks
  - `make clean` – remove binaries
- `quickstart.sh` provides an interactive guided setup and run.

---

## Project Structure

- `cmodules/`         - All C source files for evasion techniques
- `cmodules/bin/`     - Compiled binaries for each technique
- `cmodules/legacy/`  - Old/experimental C code
- `scripts/`          - Shell scripts for compiling and running tests
- `docs/`             - Documentation

---

## Tutorial: How to Build and Run the Suite

### Prerequisites

- Linux (x86_64)
- GCC (for compiling C code)
- Intel PIN ([Download here](https://www.intel.com/content/www/us/en/developer/tools/pin/download.html); download and extract, update the `PIN` variable in scripts if needed)

### 1. Compile All Techniques

From the project root, run:

```bash
./compile_all.sh
```

This will compile all C modules and place the binaries in `cmodules/bin/`.

### 2. Run All Evasions (Native and Under PIN)

From the project root, run:

```bash
./run_all_evasions.sh
```

- This will compile (if needed), then run all techniques natively and under PIN.
- Results for each technique will be displayed, along with a summary table.
- To enable verbose/debug output, use:

```bash
./run_all_evasions.sh -v
```

### 3. Alternative: Run from Build Script

You can also use:

```bash
./run_all_evasions_from_build.sh
```

This script assumes all binaries are already compiled.

### 4. Run Individual Techniques

For running a an individual technique, I recommend running one of the provided scripts located at `scripts` as they run the native version, followed by the PIN version. This illustrates some techniques better than others, mainly technique $9$ `Performance Degradation` in the time difference.

```bash
.scripts/run_perf_degradation -v
```

To run a single technique (e.g., technique 1) natively:

```bash
./cmodules/bin/1_code_cache_fingerprint -v
```

To run under PIN:

```bash
$PIN -t $TOOL -- ./cmodules/bin/1_code_cache_fingerprint -v
```

Where `$PIN` and `$TOOL` are set as in the scripts.

---

## Output

- Each technique prints standardized output markers, e.g. `[n/9] [OK]` or `[n/9] [DBI Detected ...]`.
- The master script prints a summary table showing which techniques detected DBI.

---

## Notes

- Update the `PIN` and `TOOL` variables in scripts if your PIN installation is in a different location.
- All scripts and code are modular and robust for easy extension.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This repository is for educational and research purposes only. The code and techniques provided are intended to help understand and analyze dynamic binary instrumentation (DBI) detection and evasion. Use of this code for malicious purposes is strictly prohibited.

By using this repository, you agree to:
- Use the code responsibly and ethically.
- Comply with all applicable laws and regulations in your jurisdiction.
- Not use the code to harm, disrupt, or gain unauthorized access to any system or data.

The authors and contributors are not responsible for any misuse of this code or for any damages or legal consequences that may arise from its use.
