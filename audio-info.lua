-- wireplumber script monitoring 
-- volume  |  mute  |  if bluetooth is useed

-- execute with wpexec

bt_om = ObjectManager {
  Interest { 
    type = "node",
    Constraint { "device.api", "=", "bluez5", type = "pw"} ,
  }
}

Core.require_api("default-nodes","mixer", function(default_nodes,mixer)
  function print_info()
    local id = default_nodes:call("get-default-node","Audio/Sink")
    local volume = mixer:call("get-volume",id)
    local volume_str = string.sub(tostring(volume.volume),1,4)

    local node = bt_om:lookup{Constraint {"object.id", "=", id}}
    -- if node is found, bluetooth is used
    print(volume_str .. (volume.mute and 't' or 'f') .. (node ~= nil and 't' or 'f'))
  end

  print_info()

  default_nodes:connect("changed",print_info)
  mixer:connect("changed",print_info)
end)

bt_om:activate()
