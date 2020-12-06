for mode in m a t u
do
    for file in ./testfiles/*; do
        if [ -f "$file" ]; then
            echo testing file $file
            ./packetstats -f $file -$mode > output.txt
            /u/wy/ys/promig3/pub/bin/packetstats -f $file -$mode > promigOutput.txt
            DIFF=$(diff -b -B <(sort output.txt) <(sort promigOutput.txt))
            if [ "$DIFF" != "" ]
            then
                diff -b -B output.txt promigOutput.txt > outputDifferences.txt
                echo There was a difference detected with file $file while testing for $mode
                exit
            fi
        fi
    done
done