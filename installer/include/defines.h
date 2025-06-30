#define PS4_UPDATE_FULL_PATH "/update/PS4UPDATE.PUP"
#define PS4_UPDATE_TEMP_PATH "/update/PS4UPDATE.PUP.net.temp"

#define KERN_XFAST_SYSCALL 0x1C0
#define KERN_PRISON_0 0x10986a0
#define KERN_ROOTVNODE 0x22c1a70
#define KERN_PMAP_PROTECT 0x2E3090
#define KERN_PMAP_PROTECT_P 0x2E30D4
#define KERN_PMAP_STORE 0x22CB570
#define DT_HASH_SEGMENT 0xB5EF30

#define CR0_WP (1 << 16)

int32_t (*sceKernelIsDevKit)(void);
int32_t (*sceKernelIsTestKit)(void);
int32_t (*sceKernelIsCEX)(void);

int payload_result = 0;
uint8_t *kernel_base = 0;

struct payload_info
{
  uint8_t* buffer;
  size_t size;
};

struct payload_header
{
  uint64_t signature;
  size_t entrypoint_offset;
};

struct install_payload_args
{
  void* syscall_handler;
  struct payload_info* payload_info;
};
