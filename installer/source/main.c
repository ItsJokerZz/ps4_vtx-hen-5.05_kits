#include "ps4.h"
#include "defines.h"

extern char kpayload[];
extern unsigned kpayload_size;
extern int payload_result;
extern uint8_t *kernel_base;

static inline u64 cr0_read(void)
{
  u64 reg;
  __asm__ volatile("mov %0, cr0;" : "=r"(reg));
  return reg;
}

static inline void cr0_write(u64 val)
{
  __asm__ volatile("mov cr0, %0;" ::"r"(val));
}

static inline u64 write_protect_disable(void)
{
  u64 cr0 = cr0_read();
  cr0_write(cr0 & ~CR0_WP);
  return cr0;
}

static inline void write_protect_restore(u64 cr0)
{
  cr0_write(cr0_read() | (cr0 & CR0_WP));
}

int install_payload(struct thread *td, struct install_payload_args *args)
{
  struct ucred *cred = td->td_proc->p_ucred;
  struct filedesc *fd = td->td_proc->p_fd;

  uint8_t *kbase = (uint8_t *)(__readmsr(0xC0000082) - KERN_XFAST_SYSCALL);
  uint8_t *kptr = (uint8_t *)kbase;
  void **prison0 = (void **)&kptr[KERN_PRISON_0];
  void **rootvnode = (void **)&kptr[KERN_ROOTVNODE];
  void (*pmap_protect)(void *, u64, u64, u8) = (void *)(kbase + KERN_PMAP_PROTECT);
  void *pmap_store = (void *)(kbase + KERN_PMAP_STORE);

  uint8_t *payload_data = args->payload_info->buffer;
  size_t payload_size = args->payload_info->size;
  struct payload_header *hdr = (struct payload_header *)payload_data;
  uint8_t *payload_buf = &kbase[DT_HASH_SEGMENT];

  if (!payload_data || payload_size < sizeof(*hdr) || hdr->signature != 0x5041594C4F414458ull)
    return -1;

  cred->cr_uid = cred->cr_ruid = cred->cr_rgid = 0;
  cred->cr_groups[0] = 0;
  cred->cr_prison = *prison0;
  fd->fd_rdir = fd->fd_jdir = *rootvnode;

  void *td_ucred = *(void **)(((char *)td) + 304);
  *(u64 *)((char *)td_ucred + 96) = 0xffffffffffffffff;
  *(u64 *)((char *)td_ucred + 88) = 0x3801000000000013;
  *(u64 *)((char *)td_ucred + 104) = 0xffffffffffffffff;

  u64 cr0 = cr0_read();
  cr0_write(cr0 & ~CR0_WP);

  u32 spoof_version = 0x99999999;

  if (sceKernelIsTestKit())
  {
    *(u32 *)(kbase + 0x14A63F0) = spoof_version;
    *(u32 *)(kbase + 0x1AA52D0) = spoof_version;
  }

  if (sceKernelIsDevKit())
  {
    *(u32 *)(kbase + 0x16e6d00) = spoof_version;
    *(u32 *)(kbase + 0x1ced2d0) = spoof_version;
  }

  memset(payload_buf, 0, PAGE_SIZE);
  memcpy(payload_buf, payload_data, payload_size);

  u64 sss = ((u64)payload_buf) & ~(PAGE_SIZE - 1);
  u64 eee = ((u64)payload_buf + payload_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

  kbase[KERN_PMAP_PROTECT_P] = 0xEB;
  pmap_protect(pmap_store, sss, eee, 7);
  kbase[KERN_PMAP_PROTECT_P] = 0x75;

  cr0_write(cr0);

  int (*entry)() = (void *)(&payload_buf[hdr->entrypoint_offset]);
  payload_result = entry();

  return payload_result;
}

int kernel_payload(void *uap)
{
  if (!sceKernelIsTestKit())
    return 0;

  u32 off1 = 0x1C0, off2 = 0, off3 = 0, off4 = 0;

  if (sceKernelIsTestKit())
  {
    off2 = 0x638626;
    off3 = 0x638638;
    off4 = 0x6385f0;
  }

  if (sceKernelIsDevKit())
  {
    off2 = 0x7cd316;
    off3 = 0x7cd328;
    off4 = 0x7cd2e0;
  }

  kernel_base = (uint8_t *)(__readmsr(0xC0000082) - off1);

  if (sceKernelIsDevKit())
  {
    void (*sceSblSrtcClearTimeDifference)(uint64_t) =
        (void *)(kernel_base + 0x7c9380);

    void (*sceSblSrtcSetTime)(uint64_t) =
        (void *)(kernel_base + 0x7c8d80);

    sceSblSrtcClearTimeDifference(15);
    sceSblSrtcSetTime(14861963);
  }

  u64 cr0 = write_protect_disable();

  kernel_base[off2 + 1] = 0;
  kernel_base[off3 + 1] = 0x94;

  void (*dev_act_set_status)(int) =
      (void *)(kernel_base + off4);
  dev_act_set_status(0);

  write_protect_restore(cr0);

  return 0;
}

static inline void patch_update(void)
{
  unlink(PS4_UPDATE_FULL_PATH);
  unlink(PS4_UPDATE_TEMP_PATH);
  mkdir(PS4_UPDATE_FULL_PATH, 0777);
  mkdir(PS4_UPDATE_TEMP_PATH, 0777);
}

int _main(struct thread *td)
{
  UNUSED(td);

  initKernel();
  initLibc();
  patch_update();

  enable_perm_uart();
  enable_browser();

  if (sceKernelIsCEX())
    return -1;

  RESOLVE(libKernelHandle, sceKernelIsDevKit);
  RESOLVE(libKernelHandle, sceKernelIsTestKit);
  RESOLVE(libKernelHandle, sceKernelIsCEX);

  syscall(11, kernel_payload, 0);

  struct payload_info payload_info = {
      .buffer = (uint8_t *)kpayload,
      .size = (size_t)kpayload_size,
  };

  errno = 0;
  int result = kexec(&install_payload, &payload_info);
  return result ? errno : 0;
}
