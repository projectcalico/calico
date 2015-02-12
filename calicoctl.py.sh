
_calicoctlpy()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $( compgen -W ' node status addtogroup reset diags version master addgroup' -- $cur) )
    else
        case ${COMP_WORDS[1]} in
            node)
            _calicoctlpy_node
        ;;
            status)
            _calicoctlpy_status
        ;;
            addtogroup)
            _calicoctlpy_addtogroup
        ;;
            reset)
            _calicoctlpy_reset
        ;;
            diags)
            _calicoctlpy_diags
        ;;
            version)
            _calicoctlpy_version
        ;;
            master)
            _calicoctlpy_master
        ;;
            addgroup)
            _calicoctlpy_addgroup
        ;;
        esac

    fi
}

_calicoctlpy_node()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -W '--ip= --etcd= --node-image= ' -- $cur) )
    fi
}

_calicoctlpy_status()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -W '--etcd= ' -- $cur) )
    fi
}

_calicoctlpy_addtogroup()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -fW '--etcd= ' -- $cur) )
    fi
}

_calicoctlpy_reset()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -W '--etcd= ' -- $cur) )
    fi
}

_calicoctlpy_diags()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -W ' ' -- $cur) )
    fi
}

_calicoctlpy_version()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -W '--etcd= ' -- $cur) )
    fi
}

_calicoctlpy_master()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -W '--ip= --etcd= --master-image= ' -- $cur) )
    fi
}

_calicoctlpy_addgroup()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -fW '--etcd= ' -- $cur) )
    fi
}

complete -F _calicoctlpy calicoctl.py
complete -F _calicoctlpy calicoctl
