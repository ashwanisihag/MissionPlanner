import sys

with open('Tools/AP_Bootloader/support.cpp', 'r') as f:
    content = f.read()

old = '    chnWriteTimeout(&BOOTLOADER_DEBUG, (const uint8_t *)umsg, n, chTimeMS2I(100));\n#endif\n}'
new = (
    '    chnWriteTimeout(&BOOTLOADER_DEBUG, (const uint8_t *)umsg, n, chTimeMS2I(100));\n'
    '#if defined(BOOTLOADER_DEBUG_USB_MIRROR) && BOOTLOADER_DEBUG_USB_MIRROR\n'
    '    // Mirror debug output to USB CDC (SDU1/OTG1) so GCS can capture POST on USB\n'
    '    chnWriteTimeout(&SDU1, (const uint8_t *)umsg, n, TIME_IMMEDIATE);\n'
    '#endif\n'
    '#endif\n'
    '}'
)

if old in content:
    content = content.replace(old, new, 1)
    with open('Tools/AP_Bootloader/support.cpp', 'w') as f:
        f.write(content)
    print('PATCHED OK')
else:
    print('PATTERN NOT FOUND')
    sys.exit(1)
