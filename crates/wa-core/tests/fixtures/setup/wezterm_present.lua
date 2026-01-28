local wezterm = require 'wezterm'
local config = {}

-- WA-BEGIN (do not edit this block)
-- Forward user-var events to wa daemon
wezterm.on('user-var-changed', function(window, pane, name, value)
  if name:match('^wa%-') then
    wezterm.background_child_process {
      'wa', 'event', '--from-uservar',
      '--pane', tostring(pane:pane_id()),
      '--name', name,
      '--value', value
    }
  end
end)
-- WA-END

return config
