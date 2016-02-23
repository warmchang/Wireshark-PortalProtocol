--[[ portal.lua    zsk  2012-9-2 ]]
--[[ portal.lua    zwm  2015-09-23 ]]


do
    local p_PORTAL = Proto("portal", "Portal")

    -- description table for Packet Type(Code)
    local codedesc = {
        [1] = "Request Challenge",
        [2] = "Acknowledge Challenge",
        [3] = "Request Authentication",
        [4] = "Acknowledge Authentication",
        [5] = "Request Logout",
        [6] = "Acknowledge Logout",
        [7] = "Affirmation Acknowledge Authentication",
        [8] = "Notify Logout",
        [9] = "Request Info",
        [10] = "Acknowledge Info",
        [11] = "Notify User Discover",
        [12] = "Notify User IP_Change",
        [13] = "Affirmation Notify User IP Change",
        [14] = "Acknowledge Notify Logout"
    }

    -- description table for Authentication type
    local authtypedesc = {
        [0] = "CHAP (0)",
        [1] = "PAP (1)"
    }

    local f_version = ProtoField.bytes("portal.version", "Version", base.DEC)
    local f_code = ProtoField.bytes("portal.code", "Code", base.HEX)
    local f_authtype = ProtoField.bytes("portal.authtype", "Authentication Type", base.DEC)
    local f_reserved = ProtoField.bytes("portal.reserved", "Reserved")
    local f_serialno = ProtoField.uint16("portal.serialno", "Serial Number", base.HEX)
    local f_requestid = ProtoField.uint16("portal.requestid", "Request ID", base.DEC)
    local f_useripaddr = ProtoField.uint32("portal.useripaddr", "User IP", base.HEX)
    local f_userport = ProtoField.uint16("portal.userport", "User Port", base.DEC)
    local f_errorcode = ProtoField.bytes("portal.errorcode", "Error Code", base.DEC)
    local f_attrnum = ProtoField.bytes("portal.attrnum", "Attribute Number", base.DEC)
    local f_authenticator = ProtoField.bytes("portal.authenticator", "Attribute")

    p_PORTAL.fields = { f_version, f_code, f_authtype, f_reserved, f_serialno, f_requestid, f_useripaddr, f_userport, f_errorcode, f_attrnum, f_authenticator }
    -- p_PORTAL.fields = {f_version, f_code, f_authtype, f_reserved, f_serialno, f_requestid, f_useripaddr, f_userport, f_errorcode, f_attrnum}


    -- the portal dissector function

    local function p_PORTAL_dissector(buffer, pkt, root)
        -- local buf_len = buffer:len()
        -- if buf_len < 32 then return false end -- 32 is the minimun portal packet length

        local portalFields = root:add(p_PORTAL, buffer())
        portalFields:append_text(", " .. codedesc[buffer(1, 1):uint()])

        local offset = 0

        portalFields:add(buffer(0, 1), "Version: " .. buffer(0, 1):uint())
        portalFields:add(buffer(1, 1), "Code: " .. codedesc[buffer(1, 1):uint()])
        portalFields:add(buffer(2, 1), "Authentication Type: " .. authtypedesc[buffer(2, 1):uint()])
        portalFields:add(buffer(4, 2), "Serial Number: 0x" .. buffer(4, 2))
        portalFields:add(buffer(6, 2), "Request ID: " .. buffer(6, 2):uint())
        portalFields:add(buffer(8, 4), "User IP: 0x" .. buffer(8, 4))
        portalFields:add(buffer(12, 2), "User Port: " .. buffer(12, 2):uint())
        portalFields:add(buffer(14, 1), "Error Code: " .. buffer(14, 1):uint())
        portalFields:add(buffer(15, 1), "Attribute Number: " .. buffer(15, 1):uint())
        -- portalFields:add(buffer(16, 16), "Attribute: " .. buffer(16, 16))

        local buf_len = buffer:len()
        if buf_len > 16 then
            portalFields:add(buffer(16, buf_len - 16), "Attribute: " .. buffer(16, buf_len - 16))
        end

        -- Modify the pinfo columns
        pkt.cols.protocol = p_PORTAL.name
        pkt.cols.info = string.format("%-22s", codedesc[buffer(1, 1):uint()])

        return true
    end


    function p_PORTAL.dissector(buf, pkt, root)
        if p_PORTAL_dissector(buf, pkt, root) then
            -- valid iBSC Inner diagram
        else
            -- if not my procotol, call data
            -- get the packet's data field
            local data_dis = Dissector.get("data")
            data_dis:call(buf, pkt, root)
        end
    end


    -- register to udp.port = 2000
    local portal_disc_table = DissectorTable.get("udp.port")
    portal_disc_table:add(2000, p_PORTAL)
end
