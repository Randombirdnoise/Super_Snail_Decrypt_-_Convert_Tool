python bsymg_full_pipeline_parallel_diagnostic.py ^
  "path\to\encrypted\assets" ^
  --out-dir "path\to\decrypted\assets" ^
  --key-file "path\to\xor_key_hit_0.bin" ^
  --rename-basis --transcode-basis --jobs 8 --verbose --keep "*_unpacked_a_*.png"



DEFAULT_KEEP_PATTERNS = ["*_unpacked_rgba_ASTC_RGBA_*.png"]  # keep only composite RGBA by default

*need to have Basisu on path.
In a CMD terminal (update your path accordingly)

powershell -Command "[Environment]::SetEnvironmentVariable('Path', $env:Path + ';path\to\basisu', 'User')"

Also Included is a Plist unpacker. Just place all 3 files in your decrypted root directory and run the .bat. Not all are perfectly sliced. Will tweak in future but better than nothing. 
