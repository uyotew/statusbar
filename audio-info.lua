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
  mixer["scale"] = "cubic"
  function print_info()
    local id = default_nodes:call("get-default-node","Audio/Sink")
    local volume = mixer:call("get-volume",id)
    -- avoid tostring returning a number using scientific notation
    local volume_num = (volume.volume < 0.01) and 0.0 or volume.volume
    -- add an extra 0, since it might not always be present
    local volume_str = string.sub(tostring(volume_num) ..'0',1,4)

    local node = bt_om:lookup{Constraint {"object.id", "=", id}}
    -- if node is found, bluetooth is used
    print(volume_str .. (volume.mute and 't' or 'f') .. (node ~= nil and 't' or 'f'))
  end

  print_info()

  default_nodes:connect("changed",print_info)
  mixer:connect("changed",print_info)
end)

bt_om:activate()
