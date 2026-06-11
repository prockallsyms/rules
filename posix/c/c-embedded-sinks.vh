author = "vulhunt-dev"
name = "c-embedded-sensitive-sink"
platform = "posix-binary"
architecture = "*:*:*"

-- Ported from the embedded SAST sets (freertos/zephyr/nrf-sdk + embedded/elttam).
-- Presence of SDK sinks that are dangerous in firmware contexts:
--  * unauthenticated CAN-bus frame transmission (CWE-306/CWE-345)
--  * FOTA download (verify it pins TLS / a security tag) (CWE-494)
--  * nRF modem AT command building (AT injection if input-derived) (CWE-77)
-- NOTE: UNVALIDATED — these target ARM firmware using vendor SDKs; no firmware
-- sample was available to test against. Reported as call-presence only.
scopes = {
  scope:calls{to = "can_send",                       using = {}, with = check_can},
  scope:calls{to = "can_transmit",                   using = {}, with = check_can},
  scope:calls{to = "CAN_Write",                      using = {}, with = check_can},
  scope:calls{to = "CAN_WriteFD",                    using = {}, with = check_can},
  scope:calls{to = "FLEXCAN_TransferSendBlocking",   using = {}, with = check_can},
  scope:calls{to = "fota_download_start",            using = {}, with = check_fota},
  scope:calls{to = "fota_download_start_with_image_type", using = {}, with = check_fota},
  scope:calls{to = "nrf_modem_at_printf",            using = {}, with = check_at},
  scope:calls{to = "nrf_modem_at_cmd",               using = {}, with = check_at},
  scope:calls{to = "nrf_modem_at_cmd_async",         using = {}, with = check_at},
}

local function emit(context, sev, name, desc, cwes, msg)
  return result:new(sev, "vulnerability", {
    name = name, description = desc, cwes = cwes,
    evidence = {functions = {[context.caller.address] = {
      annotate:at{location = context.caller.call_address, message = msg}}}}
  })
end

function check_can(project, context)
  return emit(context, "low", "can-bus-no-message-auth",
    "CAN-bus frame transmission. CAN has no built-in authentication; ensure application-layer message authentication. (CWE-306/CWE-345)",
    {"CWE-306", "CWE-345"}, "Unauthenticated CAN frame transmission.")
end

function check_fota(project, context)
  return emit(context, "medium", "fota-verify-transport",
    "Firmware-over-the-air download. Verify the image is delivered over TLS and validated against a security tag / signature. (CWE-494)",
    {"CWE-494"}, "FOTA download — confirm TLS + image validation.")
end

function check_at(project, context)
  return emit(context, "medium", "modem-at-injection",
    "nRF modem AT command construction. If any field derives from untrusted input this is AT-command injection. (CWE-77)",
    {"CWE-77"}, "AT command built here — verify no untrusted input.")
end
-- vim: ft=lua
