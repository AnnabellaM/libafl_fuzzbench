SEEDS_DIR="/path/to/default/queue"

echo ""
echo "Processing seed files from $SEEDS_DIR..."
SEED_COUNT=0

clang++ -fprofile-instr-generate -fcoverage-mapping -o fuzz_target fuzz_target.cpp

# Process each seed file in the queue folder
for SEED_FILE in "$SEEDS_DIR"/*; do
    # Skip if not a regular file
    [ -f "$SEED_FILE" ] || continue
    
    SEED_NAME=$(basename "$SEED_FILE")
    PROFRAW_FILE="${SEED_NAME}.profraw"
    
    echo "  Processing: $SEED_NAME"
    export LLVM_PROFILE_FILE="$PROFRAW_FILE"
    
    # Run fuzzer against this seed file
    ./fuzz_target "$SEED_FILE" > /dev/null 2>&1 || true
    
    SEED_COUNT=$((SEED_COUNT + 1))
done

if [ $SEED_COUNT -eq 0 ]; then
    echo "Warning: No seed files found in $SEEDS_DIR"
    exit 1
fi

echo ""
echo "Processed $SEED_COUNT seed files"

mkdir profraw
mv *.profraw ./profraw/
cd profraw

# Merge all profraw files
echo ""
echo "Merging profile data from all .profraw files..."
PROFRAW_COUNT=$(find . -maxdepth 1 -name "*.profraw" | wc -l)

if [ "$PROFRAW_COUNT" -eq 0 ]; then
    echo "Error: No .profraw files found"
    exit 1
fi

echo "Found $PROFRAW_COUNT .profraw files"
llvm-profdata-16 merge -sparse -output=fuzzer.profdata ./*.profraw

if [ -f "fuzzer.profdata" ]; then
    echo "✓ Successfully created fuzzer.profdata"
else
    echo "Error: Failed to create fuzzer.profdata"
    exit 1
fi

llvm-cov show ./fuzz_target \
  -instr-profile=merged.profdata \
  -show-branches=count \
  -show-line-counts \
  -format=text