# Contributing to OmniReverse Studio

Contributions are welcome. Before submitting pull requests, ensure the following guidelines are adhered to:

## Code Standards

- **Python**: Follow PEP 8 with explicit type hints (`typing.Dict`, `typing.Optional`, `typing.List`). No wildcard imports.
- **C++**: Modern C++20 with MSVC / GCC compatibility. No raw pointers without lifetime ownership semantics.
- **Error Handling**: Non-destructive operations only. Never overwrite the user's source target binary in-place.
- **Testing**: Every new disassembler, unpacker, or protocol solver engine must include a corresponding unit test under `tests/`.

## Running Local Verification

```bash
python -m pytest tests/ -v
```

All 21+ tests must pass before opening a Pull Request.
