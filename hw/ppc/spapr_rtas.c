/*
 * QEMU PowerPC pSeries Logical Partition (aka sPAPR) hardware System Emulator
 *
 * Hypercall based emulated RTAS
 *
 * Copyright (c) 2010-2011 David Gibson, IBM Corporation.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "system/system.h"
#include "system/device_tree.h"
#include "system/cpus.h"
#include "system/hw_accel.h"
#include "system/runstate.h"
#include "system/qtest.h"
#include "kvm_ppc.h"

#include "hw/ppc/spapr.h"
#include "hw/ppc/spapr_vio.h"
#include "hw/ppc/spapr_cpu_core.h"
#include "hw/ppc/ppc.h"

#include <libfdt.h>
#include <stdio.h>
#include "hw/ppc/spapr_drc.h"
#include "qemu/cutils.h"
#include "trace.h"
#include "hw/ppc/fdt.h"
#include "target/ppc/mmu-hash64.h"
#include "target/ppc/mmu-book3s-v3.h"
#include "migration/blocker.h"
#include "helper_regs.h"

static void rtas_display_character(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                   uint32_t token, uint32_t nargs,
                                   target_ulong args,
                                   uint32_t nret, target_ulong rets)
{
    uint8_t c = rtas_ld(args, 0);
    SpaprVioDevice *sdev = vty_lookup(spapr, 0);

    if (!sdev) {
        rtas_st(rets, 0, RTAS_OUT_HW_ERROR);
    } else {
        vty_putchars(sdev, &c, sizeof(c));
        rtas_st(rets, 0, RTAS_OUT_SUCCESS);
    }
}

static void rtas_power_off(PowerPCCPU *cpu, SpaprMachineState *spapr,
                           uint32_t token, uint32_t nargs, target_ulong args,
                           uint32_t nret, target_ulong rets)
{
    if (nargs != 2 || nret != 1) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }
    qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
    cpu_stop_current();
    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static void rtas_system_reboot(PowerPCCPU *cpu, SpaprMachineState *spapr,
                               uint32_t token, uint32_t nargs,
                               target_ulong args,
                               uint32_t nret, target_ulong rets)
{
    if (nargs != 0 || nret != 1) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }
    qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static void rtas_query_cpu_stopped_state(PowerPCCPU *cpu_,
                                         SpaprMachineState *spapr,
                                         uint32_t token, uint32_t nargs,
                                         target_ulong args,
                                         uint32_t nret, target_ulong rets)
{
    target_ulong id;
    PowerPCCPU *cpu;

    if (nargs != 1 || nret != 2) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    id = rtas_ld(args, 0);
    cpu = spapr_find_cpu(id);
    if (cpu != NULL) {
        if (CPU(cpu)->halted) {
            rtas_st(rets, 1, 0);
        } else {
            rtas_st(rets, 1, 2);
        }

        rtas_st(rets, 0, RTAS_OUT_SUCCESS);
        return;
    }

    /* Didn't find a matching cpu */
    rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
}

static void rtas_start_cpu(PowerPCCPU *callcpu, SpaprMachineState *spapr,
                           uint32_t token, uint32_t nargs,
                           target_ulong args,
                           uint32_t nret, target_ulong rets)
{
    target_ulong id, start, r3;
    PowerPCCPU *newcpu;
    CPUPPCState *env;
    target_ulong lpcr;
    target_ulong caller_lpcr;

    if (nargs != 3 || nret != 1) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    id = rtas_ld(args, 0);
    start = rtas_ld(args, 1);
    r3 = rtas_ld(args, 2);

    newcpu = spapr_find_cpu(id);
    if (!newcpu) {
        /* Didn't find a matching cpu */
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    env = &newcpu->env;

    if (!CPU(newcpu)->halted) {
        rtas_st(rets, 0, RTAS_OUT_HW_ERROR);
        return;
    }

    cpu_synchronize_state(CPU(newcpu));

    env->msr = (1ULL << MSR_SF) | (1ULL << MSR_ME);
    hreg_compute_hflags(env);

    caller_lpcr = callcpu->env.spr[SPR_LPCR];
    lpcr = env->spr[SPR_LPCR];

    /* Set ILE the same way */
    lpcr = (lpcr & ~LPCR_ILE) | (caller_lpcr & LPCR_ILE);

    /* Set AIL the same way */
    lpcr = (lpcr & ~LPCR_AIL) | (caller_lpcr & LPCR_AIL);

    if (env->mmu_model == POWERPC_MMU_3_00) {
        /*
         * New cpus are expected to start in the same radix/hash mode
         * as the existing CPUs
         */
        if (ppc64_v3_radix(callcpu)) {
            lpcr |= LPCR_UPRT | LPCR_GTSE | LPCR_HR;
        } else {
            lpcr &= ~(LPCR_UPRT | LPCR_GTSE | LPCR_HR);
        }
        env->spr[SPR_PSSCR] &= ~PSSCR_EC;
    }
    ppc_store_lpcr(newcpu, lpcr);

    /*
     * Set the timebase offset of the new CPU to that of the invoking
     * CPU.  This helps hotplugged CPU to have the correct timebase
     * offset.
     */
    newcpu->env.tb_env->tb_offset = callcpu->env.tb_env->tb_offset;

    spapr_cpu_set_entry_state(newcpu, start, 0, r3, 0);

    qemu_cpu_kick(CPU(newcpu));

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static void rtas_stop_self(PowerPCCPU *cpu, SpaprMachineState *spapr,
                           uint32_t token, uint32_t nargs,
                           target_ulong args,
                           uint32_t nret, target_ulong rets)
{
    CPUState *cs = CPU(cpu);
    CPUPPCState *env = &cpu->env;
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(cpu);

    /* Disable Power-saving mode Exit Cause exceptions for the CPU.
     * This could deliver an interrupt on a dying CPU and crash the
     * guest.
     * For the same reason, set PSSCR_EC.
     */
    env->spr[SPR_PSSCR] |= PSSCR_EC;
    cs->halted = 1;
    ppc_store_lpcr(cpu, env->spr[SPR_LPCR] & ~pcc->lpcr_pm);
    kvmppc_set_reg_ppc_online(cpu, 0);
    qemu_cpu_kick(cs);
}

static void rtas_ibm_suspend_me(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                uint32_t token, uint32_t nargs,
                                target_ulong args,
                                uint32_t nret, target_ulong rets)
{
    CPUState *cs;

    if (nargs != 0 || nret != 1) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    CPU_FOREACH(cs) {
        PowerPCCPU *c = POWERPC_CPU(cs);
        CPUPPCState *e = &c->env;
        if (c == cpu) {
            continue;
        }

        /* See h_join */
        if (!cs->halted || (e->msr & (1ULL << MSR_EE))) {
            rtas_st(rets, 0, H_MULTI_THREADS_ACTIVE);
            return;
        }
    }

    qemu_system_suspend_request();
    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static inline int sysparm_st(target_ulong addr, target_ulong len,
                             const void *val, uint16_t vallen)
{
    hwaddr phys = ppc64_phys_to_real(addr);

    if (len < 2) {
        return RTAS_OUT_SYSPARM_PARAM_ERROR;
    }
    stw_be_phys(&address_space_memory, phys, vallen);
    cpu_physical_memory_write(phys + 2, val, MIN(len - 2, vallen));
    return RTAS_OUT_SUCCESS;
}

static void rtas_ibm_get_system_parameter(PowerPCCPU *cpu,
                                          SpaprMachineState *spapr,
                                          uint32_t token, uint32_t nargs,
                                          target_ulong args,
                                          uint32_t nret, target_ulong rets)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(cpu);
    MachineState *ms = MACHINE(spapr);
    target_ulong parameter = rtas_ld(args, 0);
    target_ulong buffer = rtas_ld(args, 1);
    target_ulong length = rtas_ld(args, 2);
    target_ulong ret;

    switch (parameter) {
    case RTAS_SYSPARM_SPLPAR_CHARACTERISTICS: {
        g_autofree char *param_val = g_strdup_printf("MaxEntCap=%d,"
                                                     "DesMem=%" PRIu64 ","
                                                     "DesProcs=%d,"
                                                     "MaxPlatProcs=%d",
                                                     ms->smp.max_cpus,
                                                     ms->ram_size / MiB,
                                                     ms->smp.cpus,
                                                     ms->smp.max_cpus);
        if (pcc->n_host_threads > 0) {
            /*
             * Add HostThrs property. This property is not present in PAPR but
             * is expected by some guests to communicate the number of physical
             * host threads per core on the system so that they can scale
             * information which varies based on the thread configuration.
             */
            g_autofree char *hostthr_val = g_strdup_printf(",HostThrs=%d",
                                                           pcc->n_host_threads);
            char *old = param_val;

            param_val = g_strconcat(param_val, hostthr_val, NULL);
            g_free(old);
        }
        ret = sysparm_st(buffer, length, param_val, strlen(param_val) + 1);
        break;
    }
    case RTAS_SYSPARM_DIAGNOSTICS_RUN_MODE: {
        uint8_t param_val = DIAGNOSTICS_RUN_MODE_DISABLED;

        ret = sysparm_st(buffer, length, &param_val, sizeof(param_val));
        break;
    }
    case RTAS_SYSPARM_UUID:
        ret = sysparm_st(buffer, length, (unsigned char *)&qemu_uuid,
                         (qemu_uuid_set ? 16 : 0));
        break;
    default:
        ret = RTAS_OUT_NOT_SUPPORTED;
    }

    rtas_st(rets, 0, ret);
}

static void rtas_ibm_set_system_parameter(PowerPCCPU *cpu,
                                          SpaprMachineState *spapr,
                                          uint32_t token, uint32_t nargs,
                                          target_ulong args,
                                          uint32_t nret, target_ulong rets)
{
    target_ulong parameter = rtas_ld(args, 0);
    target_ulong ret = RTAS_OUT_NOT_SUPPORTED;

    switch (parameter) {
    case RTAS_SYSPARM_SPLPAR_CHARACTERISTICS:
    case RTAS_SYSPARM_DIAGNOSTICS_RUN_MODE:
    case RTAS_SYSPARM_UUID:
        ret = RTAS_OUT_NOT_AUTHORIZED;
        break;
    }

    rtas_st(rets, 0, ret);
}

struct fadump_metadata fadump_metadata;
bool is_next_boot_fadump = false;

/* Preserve the memory locations registered for fadump */
static bool fadump_preserve_mem(void) {
    target_ulong next_section_addr;
    int dump_num_sections, data_type;
    target_ulong src_addr, src_len, dest_addr;
    void *buffer;

    struct rtas_fadump_mem_struct *fdm = &fadump_metadata.registered_fdm;

    /* TODO: For safety, keep a copy of the fadump header registered
     * initially and ensure fadump header at system crash time didn't
     * change, else the header can be changed to cause a VM to crash by
     * passing custom data to intentionally crash QEMU's asserts */

    assert (fadump_metadata.fadump_registered);
    assert (fadump_metadata.fdm_addr != -1);

    cpu_physical_memory_read(fadump_metadata.fdm_addr, &fdm->header, sizeof(fdm->header));

    /* Verify that we understand the fadump header version */
    if (fdm->header.dump_format_version != cpu_to_be32(0x00000001)) {
        /* Dump format version is unknown and likely changed from the time
         * of fadump registration. Back out now. */
        return false;
    }

    dump_num_sections = be16_to_cpu(fdm->header.dump_num_sections);

    if (dump_num_sections > FADUMP_MAX_SECTIONS) {
        qemu_log_mask(LOG_GUEST_ERROR,
                "FADUMP: Too many fadump sections: %d\n", fdm->header.dump_num_sections);
        return false;
    }

    next_section_addr = fadump_metadata.fdm_addr + be32_to_cpu(fdm->header.offset_first_dump_section);

    for (int i=0; i<dump_num_sections; ++i) {
        cpu_physical_memory_read(next_section_addr, &fdm->rgn[i], sizeof(fdm->rgn[i]));
        next_section_addr += sizeof(fdm->rgn[i]);

        data_type = be16_to_cpu( fdm->rgn[i].source_data_type );
        src_addr = be64_to_cpu( fdm->rgn[i].source_address );
        src_len = be64_to_cpu( fdm->rgn[i].source_len );
        dest_addr = be64_to_cpu( fdm->rgn[i].destination_address );

        /* Reset error_flags & bytes_dumped for now */
        fdm->rgn[i].error_flags = 0;
        fdm->rgn[i].bytes_dumped = 0;

        if (be32_to_cpu(fdm->rgn[i].request_flag) != FADUMP_REQUEST_FLAG) {
            qemu_log_mask(LOG_UNIMP, "FADUMP: Skipping copying region as not requested\n");
            continue;
        }

        switch (data_type) {
        case FADUMP_CPU_STATE_DATA: {
            /* TODO: Add cpu state data */
            /* TODO: add the error checking to see if we got enough memory
             * reserved for the cpu state data *

            *static inline SpaprCpuState *spapr_cpu_state(PowerPCCPU *cpu)
             * ?*
            *     CPUPPCState *env = &cpu->env;
             *     struct CPUArchState {
    * Most commonly used resources during translated code execution first *
    target_ulong gpr[32];  * general purpose registers *
    target_ulong gprh[32]; * storage for GPR MSB, used by the SPE extension *

 */

            /**
             *
             * Good for upstream patches in qemu:
             * **
 * vmstate_register() - legacy function to register state
 * serialisation description
 *
 * New code shouldn't be using this function as QOM-ified devices have
 * dc->vmsd to store the serialisation description.
 *
 * Returns: 0 on success, -1 on failure
 *
static inline int vmstate_register(VMStateIf *obj, int instance_id,
                                   const VMStateDescription *vmsd,
                                   void *opaque)
{
    return vmstate_register_with_alias_id(obj, instance_id, vmsd,
                                          opaque, -1, 0, NULL);
}

**
 * vmstate_replace_hack_for_ppc() - ppc used to abuse vmstate_register
 *
 * Don't even think about using this function in new code.
 *
 * Returns: 0 on success, -1 on failure
 *
int vmstate_replace_hack_for_ppc(VMStateIf *obj, int instance_id,
                                 const VMStateDescription *vmsd,
                                 void *opaque);


    * fixme: should register things through the machinestate's qdev
     * interface, this is a legacy from the spaprenvironment structure
     * which predated machinestate but had a similar function *
    vmstate_register(NULL, 0, &vmstate_spapr, spapr);
    register_savevm_live("spapr/htab", VMSTATE_INSTANCE_ID_ANY, 1,
                         &savevm_htab_handlers, spapr);


             *
             */

            uint32_t num_cpus = 0;
            CPUState *cpu;
            CPUPPCState *env;
            PowerPCCPU *ppc_cpu;

            CPU_FOREACH(cpu) {
                ++num_cpus;
            }

            struct rtas_fadump_reg_save_area_header reg_save_hdr;
            reg_save_hdr.magic_number = cpu_to_be64(fadump_str_to_u64("REGSAVE"));
            reg_save_hdr.version = cpu_to_be32(1); /* Not checked be Linux */
            reg_save_hdr.num_cpu_offset = cpu_to_be32(sizeof(struct rtas_fadump_reg_save_area_header)); /* Immediately followed by num cpus */

            #define _FADUMP_NUM_PER_CPU_REGS (32 /*gprs*/ + 9 /*nia,msr,ctr,lr,xer,cr,dar,dsisr*/ + 2 /*CPUSTRT & CPUEND*/)
            #define _FADUMP_REG_ENTRIES_SIZE (num_cpus * _FADUMP_NUM_PER_CPU_REGS * sizeof(struct rtas_fadump_reg_entry))

            /* TODO: declare in a better form */
            struct rtas_fadump_reg_entry **reg_entries =
                malloc(_FADUMP_REG_ENTRIES_SIZE);
            struct rtas_fadump_reg_entry *curr_reg_entry = (struct rtas_fadump_reg_entry*)reg_entries;

            /* This must loop num_cpus time */
            CPU_FOREACH(cpu) {
                ppc_cpu = POWERPC_CPU(cpu);
                env = cpu_env(cpu);

                curr_reg_entry->reg_id = cpu_to_be64(fadump_str_to_u64("CPUSTRT"));
                /*TODO: how to access ArchCPU*/
                curr_reg_entry->reg_value = ppc_cpu->vcpu_id;
                ++curr_reg_entry;

                /* Save the GPRs */
                for (int gpr_id=0; gpr_id<32; ++gpr_id) {
#define RTAS_FADUMP_GPR_MASK	0xffffff0000000000
#define RTAS_FADUMP_GPR_SHIFT 40
#define RTAS_FADUMP_CPU_ID_MASK			((1UL << 32) - 1)

                    curr_reg_entry->reg_id = cpu_to_be64((fadump_str_to_u64("GPR") << RTAS_FADUMP_GPR_SHIFT) | gpr_id);
                    curr_reg_entry->reg_value = env->gpr[i];
                    ++curr_reg_entry;
                }

                curr_reg_entry->reg_id = cpu_to_be64(fadump_str_to_u64("NIA"));
                curr_reg_entry->reg_value = env->nip;
                ++curr_reg_entry;

                curr_reg_entry->reg_id = cpu_to_be64(fadump_str_to_u64("MSR"));
                curr_reg_entry->reg_value = env->msr;
                ++curr_reg_entry;

                curr_reg_entry->reg_id = cpu_to_be64(fadump_str_to_u64("CTR"));
                curr_reg_entry->reg_value = env->ctr;
                ++curr_reg_entry;

                curr_reg_entry->reg_id = cpu_to_be64(fadump_str_to_u64("LR"));
                curr_reg_entry->reg_value = env->lr;
                ++curr_reg_entry;

                curr_reg_entry->reg_id = cpu_to_be64(fadump_str_to_u64("XER"));
                curr_reg_entry->reg_value = env->xer;
                ++curr_reg_entry;

                /* TODO: Handle CR register */
                curr_reg_entry->reg_id = cpu_to_be64(fadump_str_to_u64("CR"));
                curr_reg_entry->reg_value = 0 /*env->spr[SPR_CR]*/;
                ++curr_reg_entry;

                curr_reg_entry->reg_id = cpu_to_be64(fadump_str_to_u64("DAR"));
                curr_reg_entry->reg_value = env->spr[SPR_DAR];
                ++curr_reg_entry;

                curr_reg_entry->reg_id = cpu_to_be64(fadump_str_to_u64("DSISR"));
                curr_reg_entry->reg_value = env->spr[SPR_DSISR];
                ++curr_reg_entry;

                curr_reg_entry->reg_id = cpu_to_be64(fadump_str_to_u64("CPUEND"));
                ++curr_reg_entry;
            }

            target_ulong addr = dest_addr;
            cpu_physical_memory_write(addr, &reg_save_hdr, sizeof(reg_save_hdr));
            addr += sizeof(reg_save_hdr);

            /* Write num_cpus */
            num_cpus = cpu_to_be32(num_cpus);
            cpu_physical_memory_write(addr, &num_cpus, sizeof(__be32));
            addr += sizeof(__be32);

            /* Write the register entries */
            cpu_physical_memory_write(addr, reg_entries, _FADUMP_REG_ENTRIES_SIZE);
            addr += _FADUMP_REG_ENTRIES_SIZE;

            break;
        }
        case FADUMP_HPTE_REGION:
            /* TODO: Add hpte state data */
            break;
        case FADUMP_REAL_MODE_REGION:
        case FADUMP_PARAM_AREA:
            /* If source and destination are same (eg. param area), leave
             * it as-is */
            if (src_addr != dest_addr) {
                /* Copy the source to destination */
                buffer = malloc(src_len + 1);
                if (buffer == NULL) {
                    qemu_log_mask(LOG_GUEST_ERROR,
                        "QEMU: Failed allocating memory for copying reserved memory regions\n");
                    fdm->rgn[i].error_flags = cpu_to_be16(FADUMP_ERROR_LENGTH_EXCEEDS_SOURCE);
                    
                    continue;
                }

                cpu_physical_memory_read(src_addr, buffer, src_len);
                cpu_physical_memory_write(dest_addr, buffer, src_len);
                free(buffer);
            }

            fdm->rgn[i].bytes_dumped = cpu_to_be64(src_len);

            break;
        default:
            qemu_log_mask(LOG_GUEST_ERROR,
                "FADUMP: Skipping unknown source data type: %d\n", data_type);

            fdm->rgn[i].error_flags = cpu_to_be16(FADUMP_ERROR_INVALID_DATA_TYPE);
        }
    }

    return true;
}

static void trigger_fadump_boot(target_ulong spapr_retcode) {
    /* Looks like, SBE stops clocks for all cores in S0.
     * See 'stopClocksS0' in SBE source code.
     * Nearest equivalent in QEMU seems to be 'pause_all_vcpus'
     */
    pause_all_vcpus();

    /* Preserve the memory locations registered for fadump */
    if (!fadump_preserve_mem()) {
        rtas_st(spapr_retcode, 0, RTAS_OUT_HW_ERROR);

        qemu_system_guest_panicked(NULL);
        return;
    }

    /* mark next boot as fadump boot */
    is_next_boot_fadump = true;
    fadump_metadata.fadump_registered = false;  /* reset registered for next boot */
    fadump_metadata.fadump_dump_active = true;

    /* TODO: Pass `mpipl` node in device tree to signify next
     * boot is an MPIPL boot */

    /* Then do a guest reset */
    /* TODO: Does SBE really do system reset or only stop
     * clocks ? OPAL seems to think that control will not come
     * to it after it has triggered S0 interrupt. */
    qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);

    rtas_st(spapr_retcode, 0, RTAS_OUT_SUCCESS);
}

/* Papr Section 7.4.9 ibm,configure-kernel-dump RTAS call */
static void rtas_configure_kernel_dump(PowerPCCPU *cpu,
                                   SpaprMachineState *spapr,
                                   uint32_t token, uint32_t nargs,
                                   target_ulong args,
                                   uint32_t nret, target_ulong rets)
{
    struct rtas_fadump_mem_struct fdm;
    target_ulong cmd = rtas_ld(args, 0);
    target_ulong fdm_addr = rtas_ld(args, 1);
    target_ulong fdm_size = rtas_ld(args, 2);

    /* Number outputs has to be 1 */
    if (nret != 1) {
        qemu_log_mask(LOG_GUEST_ERROR,
                "FADUMP: ibm,configure-kernel-dump RTAS called with nret != 1.\n");
        return;
    }

    /* Number inputs has to be 3 */
    if (nargs != 3) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    /* TODO: Ensure fdm_addr points to a valid RMR-memory buffer */

    /**
     * TODO:
     * R1–7.4.9–7. For the Configure Platform Assisted Kernel Dump Option: The platform must present the RTAS
     * property, “ibm,configure-kernel-dump-sizes” in the OF device tree, which describes how much
     * space is required to store dump data for the firmware provided dump sections, where the firmware defined
     * dump sections are:
     *  0x0001 = CPU State Data
     *  0x0002 = Hardware Page Table for Real Mode Region
     * 
     * R1–7.4.9–8. For the Configure Platform Assisted Kernel Dump Option: The platform must present the RTAS
     * property, “ibm-configure-kernel-dump-version” in the OF device tree.
     */

    switch (cmd) {
    case FADUMP_CMD_REGISTER:
        if (fadump_metadata.fadump_registered) {
            /* Fadump already registered */
            rtas_st(rets, 0, RTAS_OUT_DUMP_ALREADY_REGISTERED);
            return;
        }

        if (fadump_metadata.fadump_dump_active == 1) {
            rtas_st(rets, 0, RTAS_OUT_DUMP_ACTIVE);
            return;
        }

        if (fdm_size < sizeof(struct rtas_fadump_section_header)) {
            hcall_dprintf("FADUMP: fadump header size is invalid: %lu\n", fdm_size);
            rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
            return;
        }

        if (fdm_addr <= 0) {
            qemu_log_mask(LOG_GUEST_ERROR,
                "FADUMP: ibm,configure-kernel-dump RTAS called with invalid fdm address: %ld\n", fdm_addr);
            rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
            return;
        }

        cpu_physical_memory_read(fdm_addr, &fdm.header, sizeof(fdm.header));

        /* Verify that we understand the fadump header version */
        if (fdm.header.dump_format_version != cpu_to_be32(0x00000001)) {
            hcall_dprintf("FADUMP: Unknown fadump header version: 0x%x\n", fdm.header.dump_format_version);
            rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
            return;
        }

        fadump_metadata.fadump_registered = true;
        fadump_metadata.fadump_dump_active = false;
        fadump_metadata.fdm_addr = fdm_addr;
        break;
    case FADUMP_CMD_UNREGISTER:
        if (fadump_metadata.fadump_dump_active == 1) {
            rtas_st(rets, 0, RTAS_OUT_DUMP_ACTIVE);
            return;
        }

        fadump_metadata.fadump_registered = true;
        fadump_metadata.fadump_dump_active = false;
        fadump_metadata.fdm_addr = -1;
        break;
    case FADUMP_CMD_INVALIDATE:
        fadump_metadata.fadump_registered = false;
        fadump_metadata.fadump_dump_active = false;
        fadump_metadata.fdm_addr = -1;
        break;
    default:
        hcall_dprintf("Unknown RTAS token 0x%x\n", token);
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static void rtas_ibm_os_term(PowerPCCPU *cpu,
                            SpaprMachineState *spapr,
                            uint32_t token, uint32_t nargs,
                            target_ulong args,
                            uint32_t nret, target_ulong rets)
{
    target_ulong msgaddr = rtas_ld(args, 0);
    char msg[512];

    /* TODO: Handle if fadump is registered */
    /*
     * R1–7.4.9–3. When the platform receives an ibm,os-term RTAS call, or on a
     * system reset without an ibm,nmi-interlock RTAS call, if the platform
     * has a dump structure registered through the ibm,configure-kernel-dump
     * call, the platform must process each registered kernel dump section as
     * required and, when available, present the dump structure information to
     * the operating system through the “ibm,kernel-dump” property, updated
     * with status for each dump section, until the dump has been invalidated
     * through the ibm,configure-kernel-dump RTAS call.
     */
    /* TODO later:
     *
     * R1–7.4.9–9. For the Configure Platform Assisted Kernel Dump Option: After a dump registration is disabled
     * (for example, by a partition migration operation), calls to ibm,os-term must return to the OS as though a
     * dump was not registered.
     */
    if (fadump_metadata.fadump_registered) {
        /* If fadump boot works, control won't come back here */
        return trigger_fadump_boot(rets);
    }

    cpu_physical_memory_read(msgaddr, msg, sizeof(msg) - 1);
    msg[sizeof(msg) - 1] = 0;

    error_report("OS terminated: %s", msg);
    qemu_system_guest_panicked(NULL);

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static void rtas_set_power_level(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                 uint32_t token, uint32_t nargs,
                                 target_ulong args, uint32_t nret,
                                 target_ulong rets)
{
    int32_t power_domain;

    if (nargs != 2 || nret != 2) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    /* we currently only use a single, "live insert" powerdomain for
     * hotplugged/dlpar'd resources, so the power is always live/full (100)
     */
    power_domain = rtas_ld(args, 0);
    if (power_domain != -1) {
        rtas_st(rets, 0, RTAS_OUT_NOT_SUPPORTED);
        return;
    }

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
    rtas_st(rets, 1, 100);
}

static void rtas_get_power_level(PowerPCCPU *cpu, SpaprMachineState *spapr,
                                  uint32_t token, uint32_t nargs,
                                  target_ulong args, uint32_t nret,
                                  target_ulong rets)
{
    int32_t power_domain;

    if (nargs != 1 || nret != 2) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    /* we currently only use a single, "live insert" powerdomain for
     * hotplugged/dlpar'd resources, so the power is always live/full (100)
     */
    power_domain = rtas_ld(args, 0);
    if (power_domain != -1) {
        rtas_st(rets, 0, RTAS_OUT_NOT_SUPPORTED);
        return;
    }

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
    rtas_st(rets, 1, 100);
}

static void rtas_ibm_nmi_register(PowerPCCPU *cpu,
                                  SpaprMachineState *spapr,
                                  uint32_t token, uint32_t nargs,
                                  target_ulong args,
                                  uint32_t nret, target_ulong rets)
{
    hwaddr rtas_addr;
    target_ulong sreset_addr, mce_addr;

    if (spapr_get_cap(spapr, SPAPR_CAP_FWNMI) == SPAPR_CAP_OFF) {
        rtas_st(rets, 0, RTAS_OUT_NOT_SUPPORTED);
        return;
    }

    rtas_addr = spapr_get_rtas_addr();
    if (!rtas_addr) {
        rtas_st(rets, 0, RTAS_OUT_NOT_SUPPORTED);
        return;
    }

    sreset_addr = rtas_ld(args, 0);
    mce_addr = rtas_ld(args, 1);

    /* PAPR requires these are in the first 32M of memory and within RMA */
    if (sreset_addr >= 32 * MiB || sreset_addr >= spapr->rma_size ||
           mce_addr >= 32 * MiB ||    mce_addr >= spapr->rma_size) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    if (kvm_enabled()) {
        if (kvmppc_set_fwnmi(cpu) < 0) {
            rtas_st(rets, 0, RTAS_OUT_NOT_SUPPORTED);
            return;
        }
    }

    spapr->fwnmi_system_reset_addr = sreset_addr;
    spapr->fwnmi_machine_check_addr = mce_addr;

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static void rtas_ibm_nmi_interlock(PowerPCCPU *cpu,
                                   SpaprMachineState *spapr,
                                   uint32_t token, uint32_t nargs,
                                   target_ulong args,
                                   uint32_t nret, target_ulong rets)
{
    if (spapr_get_cap(spapr, SPAPR_CAP_FWNMI) == SPAPR_CAP_OFF) {
        rtas_st(rets, 0, RTAS_OUT_NOT_SUPPORTED);
        return;
    }

    if (spapr->fwnmi_machine_check_addr == -1) {
        qemu_log_mask(LOG_GUEST_ERROR,
"FWNMI: ibm,nmi-interlock RTAS called with FWNMI not registered.\n");

        /* NMI register not called */
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    if (spapr->fwnmi_machine_check_interlock != cpu->vcpu_id) {
        /*
         * The vCPU that hit the NMI should invoke "ibm,nmi-interlock"
         * This should be PARAM_ERROR, but Linux calls "ibm,nmi-interlock"
         * for system reset interrupts, despite them not being interlocked.
         * PowerVM silently ignores this and returns success here. Returning
         * failure causes Linux to print the error "FWNMI: nmi-interlock
         * failed: -3", although no other apparent ill effects, this is a
         * regression for the user when enabling FWNMI. So for now, match
         * PowerVM. When most Linux clients are fixed, this could be
         * changed.
         */
        rtas_st(rets, 0, RTAS_OUT_SUCCESS);
        return;
    }

    /*
     * vCPU issuing "ibm,nmi-interlock" is done with NMI handling,
     * hence unset fwnmi_machine_check_interlock.
     */
    spapr->fwnmi_machine_check_interlock = -1;
    qemu_cond_signal(&spapr->fwnmi_machine_check_interlock_cond);
    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
    migrate_del_blocker(&spapr->fwnmi_migration_blocker);
}

static struct rtas_call {
    const char *name;
    spapr_rtas_fn fn;
} rtas_table[RTAS_TOKEN_MAX - RTAS_TOKEN_BASE];

target_ulong spapr_rtas_call(PowerPCCPU *cpu, SpaprMachineState *spapr,
                             uint32_t token, uint32_t nargs, target_ulong args,
                             uint32_t nret, target_ulong rets)
{
    if ((token >= RTAS_TOKEN_BASE) && (token < RTAS_TOKEN_MAX)) {
        struct rtas_call *call = rtas_table + (token - RTAS_TOKEN_BASE);

        if (call->fn) {
            call->fn(cpu, spapr, token, nargs, args, nret, rets);
            return H_SUCCESS;
        }
    }

    /* HACK: Some Linux early debug code uses RTAS display-character,
     * but assumes the token value is 0xa (which it is on some real
     * machines) without looking it up in the device tree.  This
     * special case makes this work */
    if (token == 0xa) {
        rtas_display_character(cpu, spapr, 0xa, nargs, args, nret, rets);
        return H_SUCCESS;
    }

    hcall_dprintf("Unknown RTAS token 0x%x\n", token);
    rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
    return H_PARAMETER;
}

static uint64_t qtest_rtas_call(char *cmd, uint32_t nargs, uint64_t args,
                                uint32_t nret, uint64_t rets)
{
    int token;

    for (token = 0; token < RTAS_TOKEN_MAX - RTAS_TOKEN_BASE; token++) {
        if (strcmp(cmd, rtas_table[token].name) == 0) {
            SpaprMachineState *spapr = SPAPR_MACHINE(qdev_get_machine());
            PowerPCCPU *cpu = POWERPC_CPU(first_cpu);

            rtas_table[token].fn(cpu, spapr, token + RTAS_TOKEN_BASE,
                                 nargs, args, nret, rets);
            return H_SUCCESS;
        }
    }
    return H_PARAMETER;
}

static bool spapr_qtest_callback(CharBackend *chr, gchar **words)
{
    if (strcmp(words[0], "rtas") == 0) {
        uint64_t res, args, ret;
        unsigned long nargs, nret;
        int rc;

        rc = qemu_strtoul(words[2], NULL, 0, &nargs);
        g_assert(rc == 0);
        rc = qemu_strtou64(words[3], NULL, 0, &args);
        g_assert(rc == 0);
        rc = qemu_strtoul(words[4], NULL, 0, &nret);
        g_assert(rc == 0);
        rc = qemu_strtou64(words[5], NULL, 0, &ret);
        g_assert(rc == 0);
        res = qtest_rtas_call(words[1], nargs, args, nret, ret);

        qtest_send_prefix(chr);
        qtest_sendf(chr, "OK %"PRIu64"\n", res);

        return true;
    }

    return false;
}

void spapr_rtas_register(int token, const char *name, spapr_rtas_fn fn)
{
    assert((token >= RTAS_TOKEN_BASE) && (token < RTAS_TOKEN_MAX));

    token -= RTAS_TOKEN_BASE;

    assert(!name || !rtas_table[token].name);

    rtas_table[token].name = name;
    rtas_table[token].fn = fn;
}

void spapr_dt_rtas_tokens(void *fdt, int rtas)
{
    int i;

    for (i = 0; i < RTAS_TOKEN_MAX - RTAS_TOKEN_BASE; i++) {
        struct rtas_call *call = &rtas_table[i];

        if (!call->name) {
            continue;
        }

        _FDT(fdt_setprop_cell(fdt, rtas, call->name, i + RTAS_TOKEN_BASE));
    }
}

hwaddr spapr_get_rtas_addr(void)
{
    SpaprMachineState *spapr = SPAPR_MACHINE(qdev_get_machine());
    int rtas_node;
    const fdt32_t *rtas_data;
    void *fdt = spapr->fdt_blob;

    /* fetch rtas addr from fdt */
    rtas_node = fdt_path_offset(fdt, "/rtas");
    if (rtas_node < 0) {
        return 0;
    }

    rtas_data = fdt_getprop(fdt, rtas_node, "linux,rtas-base", NULL);
    if (!rtas_data) {
        return 0;
    }

    /*
     * We assume that the OS called RTAS instantiate-rtas, but some other
     * OS might call RTAS instantiate-rtas-64 instead. This fine as of now
     * as SLOF only supports 32-bit variant.
     */
    return (hwaddr)fdt32_to_cpu(*rtas_data);
}

static void core_rtas_register_types(void)
{
    spapr_rtas_register(RTAS_DISPLAY_CHARACTER, "display-character",
                        rtas_display_character);
    spapr_rtas_register(RTAS_POWER_OFF, "power-off", rtas_power_off);
    spapr_rtas_register(RTAS_SYSTEM_REBOOT, "system-reboot",
                        rtas_system_reboot);
    spapr_rtas_register(RTAS_QUERY_CPU_STOPPED_STATE, "query-cpu-stopped-state",
                        rtas_query_cpu_stopped_state);
    spapr_rtas_register(RTAS_START_CPU, "start-cpu", rtas_start_cpu);
    spapr_rtas_register(RTAS_STOP_SELF, "stop-self", rtas_stop_self);
    spapr_rtas_register(RTAS_IBM_SUSPEND_ME, "ibm,suspend-me",
                        rtas_ibm_suspend_me);
    spapr_rtas_register(RTAS_IBM_GET_SYSTEM_PARAMETER,
                        "ibm,get-system-parameter",
                        rtas_ibm_get_system_parameter);
    spapr_rtas_register(RTAS_IBM_SET_SYSTEM_PARAMETER,
                        "ibm,set-system-parameter",
                        rtas_ibm_set_system_parameter);
    spapr_rtas_register(RTAS_IBM_OS_TERM, "ibm,os-term",
                        rtas_ibm_os_term);
    spapr_rtas_register(RTAS_SET_POWER_LEVEL, "set-power-level",
                        rtas_set_power_level);
    spapr_rtas_register(RTAS_GET_POWER_LEVEL, "get-power-level",
                        rtas_get_power_level);
    spapr_rtas_register(RTAS_IBM_NMI_REGISTER, "ibm,nmi-register",
                        rtas_ibm_nmi_register);
    spapr_rtas_register(RTAS_IBM_NMI_INTERLOCK, "ibm,nmi-interlock",
                        rtas_ibm_nmi_interlock);

    /* Register Fadump rtas call */
    spapr_rtas_register(RTAS_CONFIGURE_KERNEL_DUMP, "ibm,configure-kernel-dump",
                        rtas_configure_kernel_dump);

    qtest_set_command_cb(spapr_qtest_callback);
}

type_init(core_rtas_register_types)
