# ~/.bashrc
export PATH=$HOME/bin:$PATH

# WA-BEGIN (do not edit this block)
# wa: OSC 133 prompt markers for deterministic state detection
__wa_prompt_start() { printf '\e]133;A\e\\'; }
__wa_command_start() { printf '\e]133;C\e\\'; }
# WA-END

alias ll='ls -la'
