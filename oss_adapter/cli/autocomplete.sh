_c3pocli_completion() {
    COMPREPLY=( $( env COMP_WORDS="${COMP_WORDS[*]}" \
                   COMP_CWORD=$COMP_CWORD \
                   _C3POCLI_COMPLETE=complete $1 ) )
    return 0
}

complete -F _c3pocli_completion -o default c3pocli;

