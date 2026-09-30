/** @file -- MmPagingAuditApp.c
This user-facing application collects information from the SMM page tables and
writes it to files.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <SeaResponder.h>
#include <SmmSecurePolicy.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PrintLib.h>
#include <Library/PcdLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/HobLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DxeServicesLib.h>

#include <Protocol/SmmCommunication.h>
#include <Protocol/MmSupervisorCommunication.h>
#include <Protocol/Tcg2Protocol.h>
#include <IndustryStandard/Tpm20.h>

#include <Guid/MemoryAllocationHob.h>
#include <Guid/EventGroup.h>
#include <Guid/SeaTestCommRegion.h>
#include <Guid/PiSmmCommunicationRegionTable.h>

VOID   *mPiSmmCommonCommBufferAddress = NULL;
UINTN  mPiSmmCommonCommBufferSize;

/**
 * @brief      Locates and stores address of comm buffer.
 *
 * @return     EFI_ABORTED if buffer has already been located, error
 *             from getting system table, or success.
 */
EFI_STATUS
EFIAPI
LocateSmmCommonCommBuffer (
  VOID
  )
{
  EFI_STATUS                            Status            = EFI_ABORTED;
  MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *SmmCommunication = NULL;

  if (mPiSmmCommonCommBufferAddress == NULL) {
    // Locate the communication buffer, if not done yet.
    Status = gBS->LocateProtocol (&gMmSupervisorCommunicationProtocolGuid, NULL, (VOID **)&SmmCommunication);

    if (EFI_ERROR (Status) || (SmmCommunication == NULL)) {
      return Status;
    }

    // Use virtual start will be identical to physical start till translate event
    mPiSmmCommonCommBufferAddress = (VOID *)SmmCommunication->CommunicationRegion.VirtualStart;
    mPiSmmCommonCommBufferSize    = EFI_PAGES_TO_SIZE (SmmCommunication->CommunicationRegion.NumberOfPages);
  }

  return Status;
} // LocateSmmCommonCommBuffer()

/**
  Measure PE image into TPM log based on the authenticode image hashing in
  PE/COFF Specification 8.0 Appendix A.

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this function will validate its data structure
  within this image buffer before use.

  @param[in] MeasureBootProtocols   Pointer to the located MeasureBoot protocol instances.
  @param[in] ImageAddress           Start address of image buffer.
  @param[in] ImageSize              Image size
  @param[in] LinkTimeBase           Address that the image is loaded into memory.
  @param[in] ImageType              Image subsystem type.
  @param[in] FilePath               File path is corresponding to the input image.

  @retval EFI_SUCCESS            Successfully measure image.
  @retval EFI_OUT_OF_RESOURCES   No enough resource to measure image.
  @retval EFI_UNSUPPORTED        ImageType is unsupported or PE image is mal-format.
  @retval other error value
**/
EFI_STATUS
EFIAPI
Tcg2MeasurePeImage (
  IN  EFI_PHYSICAL_ADDRESS  ImageAddress,
  IN  UINTN                 ImageSize
  )
{
  EFI_STATUS         Status;
  EFI_TCG2_EVENT     *Tcg2Event;
  UINT32             EventSize;
  EFI_TCG2_PROTOCOL  *Tcg2Protocol;
  UINT8              *EventPtr;

  Status    = EFI_UNSUPPORTED;
  EventPtr  = NULL;
  Tcg2Event = NULL;

  Status = gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg2Protocol);
  if (EFI_ERROR (Status) || (Tcg2Protocol == NULL)) {
    ASSERT (FALSE);
    return EFI_UNSUPPORTED;
  }

  EventSize = OFFSET_OF (EFI_TCG2_EVENT, Event);

  //
  // Determine destination PCR by BootPolicy
  //
  // from a malicious GPT disk partition
  EventPtr = AllocateZeroPool (EventSize);
  if (EventPtr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Tcg2Event                       = (EFI_TCG2_EVENT *)EventPtr;
  Tcg2Event->Size                 = EventSize;
  Tcg2Event->Header.HeaderSize    = sizeof (EFI_TCG2_EVENT_HEADER);
  Tcg2Event->Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION;
  Tcg2Event->Header.EventType     = EV_EFI_BOOT_SERVICES_APPLICATION;
  Tcg2Event->Header.PCRIndex      = 0;

  //
  // Log the PE data
  //
  Status = Tcg2Protocol->HashLogExtendEvent (
                           Tcg2Protocol,
                           PE_COFF_IMAGE,
                           ImageAddress,
                           ImageSize,
                           Tcg2Event
                           );
  DEBUG ((DEBUG_INFO, "DxeTpm2MeasureBootHandler - Tcg2 MeasurePeImage - %r\n", Status));

  if (Status == EFI_VOLUME_FULL) {
    //
    // Volume full here means the image is hashed and its result is extended to PCR.
    // But the event log can't be saved since log area is full.
    // Just return EFI_SUCCESS in order not to block the image load.
    //
    Status = EFI_SUCCESS;
  }

  if (EventPtr != NULL) {
    FreePool (EventPtr);
  }

  return Status;
}

/**
  Helper function to cross-check SMBASE-relative data across all CPUs.

  @param[in] CpuIndex  The index of the CPU to check against all others.
  @param[in] SmBase    The SMBASE of the CPU.
  @param[in] Offset    The offset from SMBASE to read the data.
  @param[in] Size      The size of the data to read.

  @retval EFI_SUCCESS            The data matches across all CPUs.
  @retval EFI_UNSUPPORTED        The size is larger than UINT64.
  @retval EFI_NOT_STARTED        The CPU hot-plug data has not been initialized yet.
  @retval EFI_NOT_READY          The specified CPU has not run yet.
  @retval EFI_SECURITY_VIOLATION The data does not match across CPUs.
**/
EFI_STATUS
CrossCheckSmBase (
  IN UINTN                 CpuIndex,
  IN EFI_PHYSICAL_ADDRESS  SmBase,
  IN UINTN                 Offset,
  IN UINTN                 Size
  )
{
  return EFI_SUCCESS;
}

#include <Guid/MmramMemoryReserve.h>

/**
  This function check if the buffer is fully inside MMRAM.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length to be checked.

  @retval TRUE  This buffer is not part of MMRAM.
  @retval FALSE This buffer is from MMRAM.
**/
BOOLEAN
EFIAPI
IsBufferInsideMmram (
  IN EFI_PHYSICAL_ADDRESS  Buffer,
  IN UINT64                Length
  )
{
  VOID *HobStart;
  EFI_STATUS Status;
  EFI_HOB_GUID_TYPE               *MmramRangesHob;
  EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  *MmramRangesHobData;
  EFI_MMRAM_DESCRIPTOR            *MmramRanges;
  UINTN                           MmramRangeCount;

  HobStart = GetHobList ();
  //
  // Extract the MMRAM ranges from the MMRAM descriptor HOB
  //
  MmramRangesHob = GetNextGuidHob (&gEfiMmPeiMmramMemoryReserveGuid, HobStart);
  if (MmramRangesHob == NULL) {
    MmramRangesHob = GetFirstGuidHob (&gEfiSmmSmramMemoryGuid);
    if (MmramRangesHob == NULL) {
      Status =  EFI_UNSUPPORTED;
      goto Exit;
    }
  }

  MmramRangesHobData = GET_GUID_HOB_DATA (MmramRangesHob);
  if (MmramRangesHobData == NULL) {
    ASSERT (MmramRangesHobData != NULL);
    Status =  EFI_NOT_FOUND;
    goto Exit;
  }

  MmramRanges     = MmramRangesHobData->Descriptor;
  MmramRangeCount = (UINTN)MmramRangesHobData->NumberOfMmReservedRegions;
  if ((MmramRanges == NULL) || (MmramRangeCount == 0)) {
    ASSERT (MmramRanges);
    ASSERT (MmramRangeCount);
    Status =  EFI_NOT_FOUND;
    goto Exit;
  }

  for (UINTN Index = 0; Index < MmramRangeCount; Index++) {
    if ((Buffer >= MmramRanges[Index].CpuStart) && ((Buffer + Length) <= (MmramRanges[Index].CpuStart + MmramRanges[Index].PhysicalSize))) {
      return TRUE;
    }
  }

  Status = EFI_SUCCESS;

Exit:
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to get MMRAM ranges - %r\n", __func__, Status));
    ASSERT (FALSE);
  }
  return FALSE;
}

STATIC
EFI_STATUS
SignalSupervisorExitBootServices (
  VOID
  )
{
  MM_SUPERVISOR_COMMUNICATION_PROTOCOL  *Communication;
  EFI_SMM_COMMUNICATE_HEADER            *Header;
  EFI_STATUS                            Status;
  UINTN                                 Size;

  if (mPiSmmCommonCommBufferSize < sizeof (EFI_SMM_COMMUNICATE_HEADER)) {
    return EFI_BAD_BUFFER_SIZE;
  }

  Status = gBS->LocateProtocol (&gMmSupervisorCommunicationProtocolGuid, NULL, (VOID **)&Communication);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Header = mPiSmmCommonCommBufferAddress;
  ZeroMem (Header, sizeof (EFI_SMM_COMMUNICATE_HEADER));
  CopyGuid (&Header->HeaderGuid, &gEfiEventExitBootServicesGuid);
  Header->MessageLength = 1;
  Header->Data[0]       = 0;
  Size                  = sizeof (EFI_SMM_COMMUNICATE_HEADER);

  return Communication->Communicate (Communication, Header, &Size);
}

/**
  The main validation routine for the SEA Core. This routine will validate the input
  to make sure the MMI entry data section is populated with legit values, then hash
  the content using TPM.

  The supervisor core will be verified to properly located inside the MMRAM region for
  this core. It will then validate the supervisor core data according to the accompanying
  aux file and revert the executed code to the original state and hash using TPM.

  @param[in]      CpuIndex           The index of the CPU.
  @param[in]      AuxFileBase        The base address of the auxiliary file.
  @param[in]      AuxFileSize        The size of the auxiliary file.
  @param[in]      MmiEntryFileSize   The size of the MMI entry file.
  @param[in]      GoldDigestList     The digest list of the MMI entry and supervisor core.
  @param[in]      GoldDigestListCnt  The count of the digest list.
  @param[in, out] PolicyBuffer       The policy buffer populated by this routine.
  @param[in, out] PolicyBufferSize   The size of policy buffer provided by the caller.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_INVALID_PARAMETER  The input parameter is invalid.
  @retval EFI_UNSUPPORTED        The input parameter is unsupported.
  @retval EFI_SECURITY_VIOLATION The input parameter violates the security policy.
  @retval other error value
**/
EFI_STATUS
EFIAPI
SeaResponderReport (
  IN  UINTN                 CpuIndex,
  IN  EFI_PHYSICAL_ADDRESS  AuxFileBase,
  IN  UINT64                AuxFileSize,
  IN  UINT64                MmiEntryFileSize,
  IN  TPML_DIGEST_VALUES    *GoldDigestList,
  IN  UINTN                 GoldDigestListCnt,
  IN OUT VOID               *PolicyBuffer OPTIONAL,
  IN OUT UINTN              *PolicyBufferSize
  );

EFI_STATUS
EFIAPI
ValidateSupervisorInSitu (
  VOID
)
{
  VOID *HobStart;
  EFI_PEI_HOB_POINTERS  Hob;
  EFI_STATUS Status;
  TPML_DIGEST_VALUES    SupvDigestList[SUPPORTED_DIGEST_COUNT];
  VOID *PolicyBuffer;
  UINTN PolicyBufferSize;

  HobStart = GetHobList ();

  // Find the supervisor location
  for (Hob.Raw = HobStart; !END_OF_HOB_LIST (Hob); Hob.Raw = GET_NEXT_HOB (Hob)) {
    if ((GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_MEMORY_ALLOCATION) &&
        (CompareGuid (
          &(Hob.MemoryAllocationModule->MemoryAllocationHeader.Name),
          &gEfiHobMemoryAllocModuleGuid
          ))) {
      DEBUG ((
        DEBUG_INFO | DEBUG_LOAD,
        "Memory Allocation Module %g\n", \
        &Hob.MemoryAllocationModule->ModuleName
        ));
    }
  }

  SupvDigestList[MMI_ENTRY_DIGEST_INDEX].digests[0].hashAlg = TPM_ALG_SHA256;
  SupvDigestList[MMI_ENTRY_DIGEST_INDEX].count              = 1;
  CopyMem (SupvDigestList[MMI_ENTRY_DIGEST_INDEX].digests[0].digest.sha256, PcdGetPtr (PcdMmiEntryBinHash), SHA256_DIGEST_SIZE);

  SupvDigestList[MM_SUPV_DIGEST_INDEX].digests[0].hashAlg = TPM_ALG_SHA256;
  SupvDigestList[MM_SUPV_DIGEST_INDEX].count              = 1;
  CopyMem (SupvDigestList[MM_SUPV_DIGEST_INDEX].digests[0].digest.sha256, PcdGetPtr (PcdMmSupervisorCoreHash), SHA256_DIGEST_SIZE);

  Status = SignalSupervisorExitBootServices ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to signal supervisor ExitBootServices - %r\n", __func__, Status));
    return Status;
  }

  PolicyBuffer     = NULL;
  PolicyBufferSize = 0;
  Status = SeaResponderReport (
            0,
            (EFI_PHYSICAL_ADDRESS)(UINTN)PcdGetPtr (PcdAuxBinFile),
            PcdGetSize (PcdAuxBinFile),
            PcdGet64 (PcdMmiEntryBinSize),
            SupvDigestList,
            SUPPORTED_DIGEST_COUNT,
            NULL,
            &PolicyBufferSize
  );

  if (Status != EFI_BUFFER_TOO_SMALL) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to prime SEA validation report routine... - %r\n", __func__, Status));
    return Status;
  }

  PolicyBuffer = AllocateZeroPool (PolicyBufferSize);
  if (PolicyBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = SeaResponderReport (
            0,
            (EFI_PHYSICAL_ADDRESS)(UINTN)PcdGetPtr (PcdAuxBinFile),
            PcdGetSize (PcdAuxBinFile),
            PcdGet64 (PcdMmiEntryBinSize),
            SupvDigestList,
            SUPPORTED_DIGEST_COUNT,
            PolicyBuffer,
            &PolicyBufferSize
  );

  FreePool (PolicyBuffer);
  return Status;
}

/**
  ResponderValidationTestAppEntry

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The entry point executed successfully.
  @retval other           Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
ResponderValidationTestAppEntry (
  IN     EFI_HANDLE        ImageHandle,
  IN     EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "%a the app's up!\n", __func__));

  if (EFI_ERROR (LocateSmmCommonCommBuffer ())) {
    DEBUG ((DEBUG_ERROR, "%a Comm buffer setup failed\n", __func__));
    return EFI_ABORTED;
  }

  Status = ValidateSupervisorInSitu ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a validation failed - %r\n", __func__, Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "%a the app's done!\n", __func__));

  return EFI_SUCCESS;
} // ResponderValidationTestAppEntry()
