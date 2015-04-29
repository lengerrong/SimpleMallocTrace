#/bin/sh
declare -A maps

myaddr2line() {
    address=$1
    binary=$2
    fa=`addr2line -e "$binary" -af "$address" | c++filt`
    echo "$fa"
}

inaddressrange() {
    address=$1
    address_range=$2
    OLD_IFS="$IFS"
    IFS="-"
    array=($address_range)
    IFS="$OLD_IFS"
    address_begin="0x${array[0]}"
    address_end="0x${array[1]}"
    let i=address-address_begin
    if [ $i -lt 0 ];then
        echo "-1"
        return
    fi
    let i=address-address_end
    if [ $i -gt 0 ];then
        echo "-1"
        return
    fi
    let i=address-address_begin;
    echo $i
}

findbinary() {
    address=$1
    for address_range in ${!maps[@]}
    do
        offset=`inaddressrange "$address" "$address_range"`
        if [ $offset -ge 0 ]; then
            binary="${maps[$address_range]}"
            # for shared libary, use offset
            if [[ "$binary" =~ ".so" ]]; then
                echo "$offset"
            else
                echo "$address"
            fi
            echo "$binary"
            return
        fi
    done
    echo "-1"
}

begintime=`date +%s`
echo "begin simple malloc trace addr2line from `date`"

if [ "$2" != "" ] ; then
    if [ -f "$2" ]; then
        while read myline
        do
            array=($myline)
            length=${#array[@]}
            valid="6"
            if [ "$length" -ge "$valid" ]; then
                address_range=${array[0]}
                address_binary=${array[5]}
                maps[$address_range]=$address_binary
            fi
        done < "$2"
    fi
fi

declare -A pmaps
if [ -f "$1" ]; then
    cat "$1" | while myline=$(line)
    do
        echo "$myline"
        if [ "${myline:0:1}" = "#" ]; then
            array=($myline)
            address=${array[1]}
            address_=$address
            fa=${pmaps[$address]}
            if [ "$fa" != "" ]; then
                echo "$fa"
            else
                binary=${array[2]}
                ab=(`findbinary "$address"`)
                abl=${#ab[@]}
                if [ $abl -gt 1 ]; then
                    aoffset=${ab[0]}
                    al=${ab[1]}
                    aoffset=`printf "0x%x" "$aoffset"`
                    if [ "$3" != "" ] ;then
                        if [ -d "$3" ]; then
                            filename=`basename "$al"`
                            nal=`find "$3" -name "$filename"`
                            if [ -f "$nal" ]; then
                                binary="$nal"
                            fi
                        fi
                    fi
                    if [ ! -f "$binary" ]; then
                        binary="$al"
                    fi
                    address=$aoffset
                fi
                if [ -f "$binary" ]; then
                    fa=`myaddr2line "$address" "$binary"`
                else
                    fa="addr2line -e $binary -af $address"
                fi
                pmaps[$address_]=$fa
                echo "$fa"
            fi
        fi
    done
fi

echo "end simple malloc trace addr2line at `date`"
endtime=`date +%s`
let usetime=endtime-begintime
echo "total use $usetime seconds"
exit
