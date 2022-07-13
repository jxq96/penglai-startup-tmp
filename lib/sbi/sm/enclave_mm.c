#include "sm/sm.h"
#include "sm/enclave.h"
#include "sm/enclave_vm.h"
#include "sm/enclave_mm.h"
#include "sbi/riscv_atomic.h"
#include "sbi/sbi_math.h"
#include "sbi/sbi_console.h"
// mm_region_list maintains the (free?) secure pages in monitor
static struct mm_region_list_t *mm_region_list;
static spinlock_t mm_regions_lock = SPINLOCK_INIT;
extern spinlock_t mbitmap_lock;
extern unsigned long to_check_point;
extern unsigned long checked_point;
extern uintptr_t pt_area_pmd_base;
extern uintptr_t pt_area_end;
extern uintptr_t pt_area_pte_base;
extern uintptr_t mbitmap_base;
extern uintptr_t mbitmap_size;

/**
 * \brief Before enclave run, need to verify whether need to scan the pt_area.
 * 
 * \param enclave Enclave to be run.
 */
void check_and_set_enclave_safety(struct enclave_t* enclave)
{
  if(enclave->checkpoint_num <= checked_point){ // checked before this enclave running.
    return;
  }
  unsigned long start, end;
  start = rdcycle();
  spin_lock(&mbitmap_lock);
  uintptr_t *pte = (uintptr_t*)(pt_area_pmd_base);
  uintptr_t *pte_end = (uintptr_t*)(pt_area_end);
  while(pte < pte_end){
    if(!IS_PGD(*pte) && PTE_VALID(*pte)){
      uintptr_t pfn = PTE_TO_PFN(*pte);
      pfn = pfn - ((uintptr_t)DRAM_BASE >> RISCV_PGSHIFT);
      if(IS_LEAF_PTE(*pte)){
        page_meta * meta = (page_meta*)(mbitmap_base) + pfn;
        if(IS_PRIVATE_PAGE(*meta)){
          *pte = INVALIDATE_PTE(*pte);
        }
      }
    }
    pte += 1;
  }
  checked_point = to_check_point;
  spin_unlock(&mbitmap_lock);
  end = rdcycle();
  sbi_printf("check_and_set_enclave_safety: %ld\n", end - start);
}

/**
 * \brief This function will turn a set of untrusted pages to secure pages.
 * Frist, it will valiated the range is valid.
 * Then, it ensures the pages are untrusted/public now.
 * Afterthat, it updates the metadata of the pages into secure (or private).
 * Last, it unmaps the pages from the host PTEs.
 *
 * FIXME: we should re-consider the order of the last two steps.
 * 
 * \param paddr the check physical address. 
 * \param size the check physical size
 */
int check_and_set_secure_memory(unsigned long paddr, unsigned long size)
{
  int ret = 0;
  if(paddr & (RISCV_PGSIZE-1) || size < RISCV_PGSIZE || size & (RISCV_PGSIZE-1))
  {
    ret = -1;
    return ret;
  }

  spin_lock(&mbitmap_lock);
  #ifdef PROFILE_MONITOR
  unsigned long start[3], end[3];
  start[0] = rdcycle();
  #endif
  if(test_public_range(PADDR_TO_PFN(paddr), size >> RISCV_PGSHIFT) != 0)
  {
    ret = -1;
    goto out;
  }
  #ifdef PROFILE_MONITOR
  end[0] = rdcycle();
  start[1] = end[0];
  #endif
  set_private_range(PADDR_TO_PFN(paddr), size >> RISCV_PGSHIFT);
  #ifdef PROFILE_MONITOR
  end[1] = rdcycle();
  start[2] = end[1];
  #endif
  unmap_mm_region(paddr, size);
  #ifdef PROFILE_MONITOR
  end[2] = rdcycle();
  sbi_printf("test public range: %ld\n", end[0] - start[0]);
  sbi_printf("set private range: %ld\n", end[1] - start[1]);
  sbi_printf("unmap_mm_region: %ld\n", end[2] - start[2]);
  #endif
  

out:
  spin_unlock(&mbitmap_lock);
  return ret;
}


/**
 * \brief Set the secure memory range in bitmap but don't check the pt_area.
 * 
 * \param paddr range start physical address.
 * \param size  memory range size.
 * \return int 
 */
int set_secure_memory(unsigned long paddr, unsigned long size, struct enclave_t *enclave)
{
  int ret = 0;
  unsigned long start, end;
  start = rdcycle();
  //Is it suitable to use unlikely here?
  if(unlikely(paddr & (RISCV_PGSIZE-1) || size < RISCV_PGSIZE || size & (RISCV_PGSIZE-1))){
    ret = -1;
    return ret;
  }
  spin_lock(&mbitmap_lock);
  if(test_public_range(PADDR_TO_PFN(paddr), size >> RISCV_PGSHIFT) != 0){
    ret = -1;
    goto out;
  }
  set_private_range(PADDR_TO_PFN(paddr), size >> RISCV_PGSHIFT);
  to_check_point += 1;
  enclave->checkpoint_num = to_check_point;
  //FIXME: initial __free_secure_memory function without locking may have concurrent problem with global pt_area scan phase.
out:
  spin_unlock(&mbitmap_lock);
  end = rdcycle();
  sbi_printf("set_secure_memory: %ld\n", end - start);
  return ret;
}

/**
 * \brief unset the memory range in bitmap.
 * 
 * \param paddr range start physical address.
 * \param size range size.
 */
void unset_secure_memory(unsigned long paddr, unsigned long size)
{
  //need lock because MAKE_PUBLIC_PAGE operation is not atomic. seems acquire lock here is very inefficient
  //but unset_secure_memory is rarely called.
  spin_lock(&mbitmap_lock);
  set_public_range(PADDR_TO_PFN(paddr), size >> RISCV_PGSHIFT);
  spin_unlock(&mbitmap_lock);
}


/**
 * \brief Free a set of secure pages.
 * It turn the secure pgaes into unsecure (or public)
 * and remap all the pages back to host's PTEs.
 * 
 * \param paddr The free physical address.
 * \param size The free memory size. 
 */
int __free_secure_memory(unsigned long paddr, unsigned long size)
{
  int ret = 0;

  set_public_range(PADDR_TO_PFN(paddr), size >> RISCV_PGSHIFT);
  remap_mm_region(paddr, size);
  return ret;
}

/**
 * \brief Free a set of secure pages.
 * It turn the secure pgaes into unsecure (or public)
 * and remap all the pages back to host's PTEs.
 * 
 * \param paddr The free physical address.
 * \param size The free memory size. 
 */
int free_secure_memory(unsigned long paddr, unsigned long size)
{
  int ret = 0;
  spin_lock(&mbitmap_lock);

  set_public_range(PADDR_TO_PFN(paddr), size >> RISCV_PGSHIFT);
  remap_mm_region(paddr, size);

  spin_unlock(&mbitmap_lock);
  return ret;
}

/**
 * \brief mm_init adds a new range into mm_region_list for monitor/enclaves to use.
 * 
 * \param paddr The init physical address.
 * \param size The init memory size. 
 */
uintptr_t mm_init(uintptr_t paddr, unsigned long size)
{
  uintptr_t ret = 0;
  spin_lock(&mm_regions_lock);

  if(size < RISCV_PGSIZE || (paddr & (RISCV_PGSIZE-1)) || (size & (RISCV_PGSIZE-1)))
  {
    ret = -1;
    goto out;
  }

  if(check_and_set_secure_memory(paddr, size) != 0)
  {
    ret = -1;
    goto out;
  }

  struct mm_region_list_t* list = (struct mm_region_list_t*)paddr;
  list->paddr = paddr;
  list->size = size;
  list->next = mm_region_list;
  mm_region_list = list;

out:
  spin_unlock(&mm_regions_lock);
  return ret;
}

/**
 * \brief mm_alloc returns a memory region
 * The returned memory size is put into resp_size, and the addr in return value.
 * 
 * \param req_size The request memory size.
 * \param resp_size The response memory size. 
 */
void* mm_alloc(unsigned long req_size, unsigned long *resp_size)
{
  void* ret = NULL;
  spin_lock(&mm_regions_lock);

  if(!mm_region_list)
  {
    ret = NULL;
    goto out;
  }

  ret = (void*)(mm_region_list->paddr);
  *resp_size = mm_region_list->size;
  mm_region_list = mm_region_list->next;

out:
  spin_unlock(&mm_regions_lock);
  return ret;
}

/**
 * \brief mm_free frees a memory region back to mm_region_list.
 * 
 * \param paddr The physical address need to be reclaimed.
 * \param size The reclaimed memory size. 
 */
int mm_free(void* paddr, unsigned long size)
{
  int ret = 0;
  spin_lock(&mm_regions_lock);

  if(size < RISCV_PGSIZE || ((uintptr_t)paddr & (RISCV_PGSIZE-1)) != 0)
  {
    ret = -1;
    goto out;
  }

  struct mm_region_list_t* list = (struct mm_region_list_t*)paddr;
  list->paddr = (uintptr_t)paddr;
  list->size = size;
  list->next = mm_region_list;
  mm_region_list = list;

out:
  spin_unlock(&mm_regions_lock);
  return ret;
}

/**
 * \brief grant enclave access to enclave's memory, it's an empty function now.
 * 
 * \param paddr The physical address need to be reclaimed.
 * \param size The reclaimed memory size. 
 */
int grant_enclave_access(struct enclave_t* enclave)
{
  return 0;
}

/**
 * \brief It's an empty function now.
 * 
 * \param enclave The current enclave. 
 */
int retrieve_enclave_access(struct enclave_t *enclave)
{
  return 0;
}
