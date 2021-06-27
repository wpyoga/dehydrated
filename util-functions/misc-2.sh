hookscript_bricker_hook() {
  # Hook scripts should ignore any hooks they don't know.
  # Calling a random hook to make this clear to the hook script authors...
  if [[ -n "${HOOK}" ]]; then
    "${HOOK}" "this_hookscript_is_broken__dehydrated_is_working_fine__please_ignore_unknown_hooks_in_your_script" || _exiterr "Please check your hook script, it should exit cleanly without doing anything on unknown/new hooks."
  fi
}
