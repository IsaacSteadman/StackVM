
namespace stackvm {
  namespace ioint {
    typedef unsigned long long ui64;
    typedef unsigned int ui32;
    typedef unsigned short ui16;
    typedef unsigned char ui8;
    const ui32 TYPE_PROCESSOR = 0;
    const ui32 TYPE_VIDEO_OUT_BASIC = 1;
    const ui32 TYPE_KEYBOARD_BASIC = 2;
    const ui32 TYPE_MOUSE_BASIC = 3;
    const ui32 TYPE_AUDIO_OUT_BASIC = 4;
    const ui32 TYPE_AUDIO_IN_BASIC = 5;
    const ui32 TYPE_POWER_MANAGEMENT = 6;
    const ui32 TYPE_STORAGE_IO_BASIC = 7;
    const ui32 TYPE_GFX_HELPER = 8;
    struct BaseDeviceInfo {
      ui32 type_dev_id[2];
    };
    struct UnknownDeviceInfo {
      BaseDeviceInfo bdi;
      ui64 reserved[7];
    };
    struct BaseDeviceCommand {
      ui32 dev_id_cmd[2];

      // set to 0 to not trigger an interrupt upon completion
      // set to non-0 to trigger an interrupt upon completion
      //   with `idata_ext` passed into the interrupt
      ui64 idata_ext;
    };
    const ui64 INT_REASON_CMD_COMPLETE = 0;
    struct BaseInterruptInfo {
      ui32 dev_id_int_reason[2];
      ui64 reason;
      ui64 timestamp_ns;
    };
    struct UnknownInterruptInfo {
      BaseDeviceInfo bii;
      ui64 reserved[8];
    };
    struct CmdCompleteInterruptInfo {
      BaseInterruptInfo bii;
      ui32 original_cmd_unused[2];
      ui64 idata_ext;
    };
    namespace processor {
      struct DeviceInfo {
        BaseDeviceInfo bdi;
        ui64 addr_hw_int_data;
        ui64 host_physical_package_id;
        ui64 features;
        ui64 reserved[4];
      };
      const ui32 CMD_ISSUE_NEW_DEVICE_INTS = 1;
      struct CmdIssueNewDeviceInts {
        BaseDeviceCommand bdc;
      };
      const ui64 INT_REASON_NEW_DEV = 1;
      struct IntDeviceAdded {
        BaseInterruptInfo bii;
        UnknownDeviceInfo device_added_info;
      };
    }
    namespace video_out_basic {
      struct DeviceInfo {
        BaseDeviceInfo bdi;
        ui32 dimensions[2];
        ui64 features;
        ui64 reserved[5];
      };
      const ui32 CMD_ISSUE_HW_UPDATE_INT = 1;
      struct CmdIssueHwUpdateInt {
        BaseDeviceCommand bdc;
      };
      const ui32 CMD_SET_MODE = 2;

      // only valid in text mode (set with CMD_SET_MODE)
      const ui32 CMD_TXT_WRITE_CHAR = 3;
      struct CmdTxtWriteChar {
        BaseDeviceCommand bdc;
        ui16 utf16f_utf16l_posx_posy[4];
      };

      // only valid in pixel mode (set with CMD_SET_MODE)
      const ui32 CMD_PIX_BLIT_FROM_MEMORY = 3;
      struct CmdPixBlitFromMemory {
        BaseDeviceCommand bdc;
        ui64 source_addr;
        ui64 source_pitch;
        ui32 source_dims[2];
        ui32 target_xy[2];
      };
    }
    namespace keyboard_basic {
      struct DeviceInfo {
        BaseDeviceInfo bdi;
        ui64 keyboard_layout;
        ui64 reserved[5];
      };
      struct CmdInterruptOnKeyChange {
        BaseDeviceCommand bdc;
        ui64 enable;
      };
      struct IntKeyDown {
        BaseInterruptInfo bii;
        ui32 keycode_mods[2];
      };
    }
    namespace storage_io_basic {
      struct DeviceInfo {
        BaseDeviceInfo bdi;
        ui64 uuid[2];
        ui64 num_sectors;
        ui8 ss_qd_nch_bi_unused[32];
        // ss means sector size (0: 1, 9: 512, 10: 1KiB, ..., 12: 4KiB, ..., 16: 64KiB, ..., 20: 1 MiB, ..., 30: 1 GiB)
        // qd means queue depth
        // nch means num channels minus 1 (255 = 256 channels)
        // bi means boot info (0x1 mask indicates bootability)
        // unused is the rest of the array of bytes
      };
      struct CmdReadInto {
        BaseDeviceCommand bdc;
        ui64 sector_addr;
        ui64 num_sectors;
        ui64 buf_phys_addr;
      };
      struct CmdWriteFrom {
        BaseDeviceCommand bdc;
        ui64 sector_addr;
        ui64 num_sectors;
        ui64 buf_phys_addr;
      };
      struct CmdGetInfo {
        BaseDeviceCommand bdc;
      };
    }
  }
}