_comp_statusbar() {
  local cur="$2"
  local prev="$3"

  if [ "--start" == "${COMP_WORDS[1]}" ]; then return; fi

  if [ $COMP_CWORD -eq 1 ]; then
    COMPREPLY+=($(compgen -W "--start" -- "$cur"))
  fi

  case "$prev" in
  "--name"|"--retain") return;;
  esac

  # would be nice if completion for the command argument
  # was possible
  # running its completion functions with the rest of the input
  local i=1
  while [ $i -lt $COMP_CWORD ]; do
    case ${COMP_WORDS[$i]} in
      "--log"|"--no-name");;
      "--name"|"--retain") i=$(( $i + 1 ));;
      *) return;;
    esac
    i=$(( $i + 1 ))
  done

  COMPREPLY+=($(compgen -c -W "--log --name --no-name --retain"  -- "$cur"))
}

complete -o nosort -F _comp_statusbar statusbar
