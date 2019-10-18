# <a name="section-1"></a> 1. PSA Trusted Storage Linux Low Level Design

Copyright © 2019 Arm Limited.

This document provides details of the recovery algorithm.

### Robustness Against Power Failure (RAPF)


The current design is not Robust Against Power Failure (RAPF) because the Linux filesystem underlying ecryptfs (i.e. ext4) is susceptible to being left in an inconsistent state. This is because the filesystem is not transactional i.e. the filesystem metadata on the backing store requires more than 1 write operation to go from one self consistent state to the next. This can, for example, lead to the loss of a file being updated at a critical point in the updating of filesystem metadata. Tools like fsck exist to restore filesystem metadata consistency when corruption of these data structures takes places.

A solution is to have a RAPF filesystem e.g. YAFFS2, and to have one or more dedicated partitions use the file system for logging PSA storage object data.
RAPF in the Absence of a Transactional Filesystem

The current design implements a file object backup strategy to mitigate data file loss inherent in using the ext4 (non-transactional) filesystem.

The starting conditions are as follows:

1.    A file object exists called file1.dat, which has a backup file called file1.bak.x where x={0,1}. file1.tmp and file1.bak.x have identical object data.
1.    file1.dat contains metadata that identifies its backup file as file1.bak.x. This is shown as the dotted line between file1.dat and file1.bak.x in the above diagram. If the file1.dat file is lost and the file.bak.x file is present then file1.bak.x is copied to recreate file1.dat.

When file object data is modified with the psa_xx_set() function then a file object Modification Procedure takes place on file1.dat with backup file file1.bak.yyy where yyy is a sequence number. The modification procedure is the following sequence of operations:

1.    file1.dat is copied to a temporary file e.g. file1.tmp.
1.    file1.tmp is modified with the set() operation.
1.    file1.tmp's pointer (stored in the file metadata inside the file) is switched to point to a new backup file1.bak.yyy+1. Note, this happens before file1.bak.yyy+1 has been created to aid in the recovery procedure.
1.    file1.tmp is copied to a create a new backup file file1.bak.yyy+1.
1.    An atomic rename() operation is used to replace file1.dat with file1.tmp. The set() operation has been sealed.
1.    The old backup file file1.bak.yyy is deleted. This is the file with the earlier modification timestamp (sequence number).

The algorithm relies on the fact that the system switches to using both the new version of file1.dat (and the new up-to-date backup file1.bak.yyy+1) in one atomic operation by using the rename() function. This can occur because the file points to its current backup file (e.g by virtue of the .dat file always using the .bak file with the latest sequence number).
Recovery Process

In summary, the recovery process attempts to restore the latest version of a file object data, and maintain a backup copy by:

1. Recovering any missing xxxx.dat.
    1. If xxxx.bkx(new) exists then use it to recreate xxxx.dat using the modification procedure.
    1. If xxxx.bkx(old) exists then use it to recreate xxxx.dat using the modification procedure.
1.    Recovering any missing xxxx.bkx.
	1. if xxxx.dat exists then use it to recreate xxxx.bkx using the modification procedure.

An explanation of the above is provide in the following.

Note that while the following analysis and discussion uses timestamps to define the recovery algorithm, there is a requirement that file timestamps are not actually used in the recovery algorithm. This is because the recovery process must function even if time is not available on the IoT device. Therefore the Modification Procedure sequencing in time is recorded using a sequence number on relevant files (only *.bkx need them). The following terms are therefore defined:

	Td=timestamp of xxxx.dat
	Td(new)=new xxxx.dat(old). This is the xxxx.dat(old) updated with the set() data.
	Td(old)=starting xxxx.dat(old).
	Tb(old)=timestamp of old xxxx.bkx.yyy files.
	Tb(new)=timestamp of new xxxx.bkx.yyy+1 file.
	Tt=timestamp of xxxx.tmp.

Note this is the order of the creation of the files:

	Td(new) > Tb(new) > Tt > Td(old) > Tb(old)

where:

	Td(new) = timestamp of xxxx.dat(new)
	Tb(new) = timestamp of xxxx.yyy.bkx(new)
	Tt = timestamp of xxxx.tmp
	Td(old) = timestamp of xxxx.dat(old)
	Tb(old) = timestamp of xxxx.yyy.bkx(old)

and either Td(new) or Td(old) exists but not both at the same time.

For the modification procedure the following combinations of files are normally present at the end of each step.

0. Td(old), Tb(old) where Td(old) -> Tb(old)
1. Td(old), Tb(old) where Td(old) -> Tb(old), Tt
2. Td(old), Tb(old) where Td(old) -> Tb(old), Tt+set()
3. Td(old), Tb(old) where Td(old) -> Tb(old), Tt+set()->Tb(new) where Tb(new) doesnt exist.
4. Td(old), Tb(old) where Td(old) -> Tb(old), Tt+set()->Tb(new)
5. Td(new), Tb(old), Tb(new) where Td(new) -> Tb(new)
6. Td(new), Tb(new) where Td(new) -> Tb(new)

Note the Modification Procedure can be interrupted at any stage by power failing. As filesystem loss and corruption can occur, this can result in:

1. The loss or retention of any combination of files taken from the set {xxxx.dat(old), xxxx.bak.yyy, xxxx.bak.yyy+1, xxxx.tmp} before the end of step 5, or 
1. The loss or retention of any combination of files taken from the set {xxxx.bak.yyy, xxxx.bak.yyy+1, xxxx.dat(new)} after the end of step 5. 

The algorithm is designed to be robust in all these possible combinations of remaining files to recover the latest possible version of the data.

Of interest are the following:

1. case 1: Td(new) > Tb(new) > Tb(old)
1. case 2: Tb(new) > Tt > Td(old) > Tb(old)

In case 1 the Td(old) has been rename() atomically to Td(new), no xxxx.dat remains, xxxx.bkx(old) may remain if not already deleted.
In case 2 the rename() has not taken place yet.

Is it possible to have a xxxx.dat file and a xxxx.tmp file at the same time? Yes, BUT:

	xxxx.dat(new) and xxxx.tmp cannot exist at the same time,

because rename() is used to atomically rename file.tmp to file.dat. So if xxxx.dat and xxxx.tmp files exist then xxxx.dat file is the xxxx.dat(old).

However, the xxxx.tmp file can never be used to restore the xxxx.dat file. This is for the following reasons:

1. If xxxx.bkx.yyy+1 (new) exists (i.e. Tb>Tt or Tb>Td) then xxxx.bkx.yyy+1 (new) can be used to restore xxxx.dat instead of xxxx.tmp.
1. If xxxx.bkx.yyy+1 (new) doesn't exists but xxxx.tmp does  (i.e. optionally a xxxx.bkx.yyy (old) can exist with Tb(old)<Tt) then the state of xxxx.tmp is unknown because 1) power could have been lost before the setting of data in xxxx.tmp had been completed (if the xxxx.tmp pointer points to a bak file and this file exists indicating the set() has been finished then Tb(new)>Tt, but the existence of this bak file contravenes the condition of this point 2 i.e. that xxxx.bkx(new) doesn't exist).

Another way of stating point 1 above is as follows. If there is only 1 xxxx.bak file then it may be bak(old) or bak(new).  There is the possibility that 1) the power failed after the end of step 4 but before the end of step 6, and 2) file system corruption leads to the loss of bak(new) but the retention of bak(old). This possibility is considered improbable but can be covered by checking that the xxxx.dat linked bak file. If the linked bak file is not the existing bak file, then the bak file is newer than the dat file and should be used to recover the xxxx.dat file.

Hence a summary of rules for recovery can be stated as follows:

1.     A. xxxx.tmp file can never be used to restore the xxxx.dat file. If any xxxx.tmp files exist then delete them.
1.     B. if there is a xxxx.bkx file with Tb>Td (for the case where xxxx.dat exists) or Tb>Tt (for the case where xxxx.tmp exists) then xxxx.bkx can be used to restore xxxx.dat.
1.     C. xxxx.dat(new) and xxxx.tmp cannot exist at the same time.
1.     D. A missing xxxx.dat can be recovered if there is at least 1 xxxx.bkx file.
1.     E. A missing xxxx.bkx can be regenerated with a xxxx.dat.

#### Scenario 1: Missing xxxx.dat

In a situation where there is 1 or more of {xxxx.bak.0, xxxx.bak.1, xxxx.tmp} but no xxxx.dat then the xxxx.dat can be recovered as follows:

1.     If there are 2 bak files then use the most recent to create xxxx.dat (Rule B, D).
1.     Else if there is 1 xxxx.bak then use it to create xxxx.dat (Rule D).

Note that if the the xxxx.bkx used for recovery has F_WRITE_ONCE flag set then 1) above can be skipped:

1. This can be true. The modification procedure is used to create xxxx.dat again and 2 it is still possible to have 2 bak files (left due to an interrupt attempt to recreate a lost xxxx.dat from a xxxx.bak).
1. This can be true and should be used.

#### Scenario 2: xxxx.dat Not Missing, Backup File xxxx.bak Possibly Missing

In the case where a xxxx.dat file exists then the following processing is performed:

1.     if there are 2 xxxx.bkx files, then check that xxxx.bkx+1 and xxxx.dat have the same sequence numbers. if this is not the case then recover the outdated xxxx.dat/xxxx.bkx+1 with the latest xxxx.bkx+1/xxxx.dat respectively.
1.     Else if there is 1 xxxx.bkx file then check that xxxx.bkx and xxxx.dat have the same sequence numbers. Otherwise, regenerate xxxx.dat/xxxx.bkx with xxxx.bkx/xxxx.dat respectively.
1.     Else if there is no xxxx.bkx file (e.g. logst due to FS corruption) then recreate it using xxxx.dat.

Note that if the the xxxx.xxx used for recovery has F_WRITE_ONCE flag set then 1) above can be skipped: F_WRITE_ONCE processing.

1. Processing is simplified. There can only 2 xxxx.bkx files & xxxx.dat if the a) xxxx.dat has previously been lost and its xxxx.bk(old) still exists b) recovery processing wrote xxxx.dat and xxxx.bkx+1(old) but failed to remove xxxx.bkx(old). In this situation, just remove the xxx.bkx(old).
1. Processing not affected.
1. Processing not affected.

#### Other Processing

The implementation then counts the number of *.dat files and sets the file count variable. It also counts the total size of all the files. These variables limit resource usage against configured limits to mitigate against filesystem storage exhaustion.

Note that in the case that the get(), get_info(), set(), remove() are called with a uid and the associated file object cannot be found, no processing is initiated to use an existing *.bak.x file for recovery. This is only performed at startup. This is considered to be a more secure approach so that an attacker cannot try to subvert the recovery process on each file object access.


#### Recovery Process Pseudo-Code


/* Pseudo-code for implementing recovery algorithm
 *
	    NB: dat file contains sequence number of linked bak file.
	
	    scandir( dirname, &xxx_list, psa_cs_xxx_file_filter, versionsort );
	    - get dat_list
	    - get bk0_list
	    - get bk1_list
	    - get tmp_list
	    - get bad_list
	
	    - delete all tmp files
	    - delete all bad files.
	
	    - list will be sorted in ascending uid order
	      using (top entry)->d_name on each list find min of (dat_list, bk0_list, bk1_list tmp_list)
	      on the uid part of the filename i.e. get the min uid filename without extension.
	      min_uid = find uid of min file.
	
	    find b_min_uid_dat_exists
	    find b_min_uid_bka_exists (the first bak file found is bka)
	    find b_min_uid_bkb_exists (the second bak file (if found) is bkb)
	        // note bka MAY be bkx or bkx+1
	        // note if b_min_uid_bkb_exists (i.e. found) then bkx+1 exists.
	    find b_min_uid_bad_exists           // can be used to detect power failure but not recovery
	    find b_min_uid_tmp_exists           // can be used to detect power failure but not recovery
	
	    if ! b_min_uid_dat_exists
	    {
	        // Scenario 1
	        // no dat exists
	
	        if b_min_uid_bka_exists && b_min_uid_bkb_exists
	        {
	            // Scenario 1.1
	            // no dat exist
	            // bkx+1 MUST exist.
	            find bkx+1 from bka, bkb based on sequence number (sequence number in file or as part of filename)
	            recover dat with bkx+1. // can use _set() here even if with WRITE_ONCE set as no dat exists.
	            remove old bak files.
	        }
	        if b_min_uid_bka_exists
	        {
	            // Scenario 1.2
	            // no dat exist
	            // only bka exists
	            recover dat with bka. // can use _set() here even if with WRITE_ONCE set as no dat exists.
	            remove any old bak files.
	        }
	        else
	        {
	            // no recovery possible
	            report error detected but no possible recovery ?
	        }
	    }
	    else
	    {
	        // Scenario 2
	        // dat exists
	
	        if b_min_uid_bka_exists && b_min_uid_bkb_exists
	        {
	            // Scenario 2.1
	            // dat exist
	            // bkx+1 MUST exist.
	            find bkx+1 from bka, bkb based on sequence number (sequence number in file or as part of filename)
	            find dat_seqnum
	            if bkx+1_seqnum > dat_seqnum
	                recreate xxxx.dat with xxxx.bkx+1
	            else
	                recreate xxxx.bak file with latest data in xxxx.dat
	        }
	        if b_min_uid_bka_exists
	        {
	            // Scenario 2.1
	            // dat exist
	            // only bka exists
	            find bka_seqnum
	            find dat_seq
	            if dat_seqnum < bka_seqnum
	                recover dat with bka.
	        }
	        else
	        {
	            // Scenarion 2.2
	            // dat exists
	            // no bak exists
	            copy dat to create new bak file
	        }
	    }
	
	cleanup:
	    if b_min_uid_tmp_exists
	        // tmp exists but recovery not possible
	        // report lost file
	        remove xxxx.tmp
	
	    if b_min_uid_bad_exists
	        // bad exists
	        // report lost file
	        remove xxxx.bad



#### Recovery Test Cases

These are the defined module test case for the recovery processing:
- Test case 1 missing dat, 2 .bak files exists: recover .dat file with latest bak_seqnum
  - no dat_seqnum, bk1_seqnum=2, bk2_seqnum=3, 
  - no dat_seqnum, bk1_seqnum=254, bk2_seqnum=255, 
  - no dat_seqnum, bk1_seqnum=255, bk2_seqnum=0, 
- Test case 2 missing dat, 1 .bak file exists: recover .dat file
  - no dat_seqnum, bk1_seqnum=2 
  - no dat_seqnum, bk1_seqnum=255 
- Test case 3 missing dat, 0 .bak file exists, .tmp file present: report error
  - no dat_seqnum, no bk1_seqnum
- Test case 4 missing dat, 0 .bak file exists, 0 .tmp file, 1 .bad file present: report error
  - no dat_seqnum, 0 bkx_seqnum, ? tmp_seqnum=?, ? bad_seqnum
- Test case 5 missing dat, 0 .bak file exists, 0 .tmp file, 1 .bad file present: report error
  - no dat_seqnum, large number of bak files (16), the last is used for recreating dat, and all others get deleted.

- Test case 51 dat present, 2 bak files: dat file up to date: check xxxx.bk(old) is removed
  - dat_seqnum=3, bk1_seqnum=2, bk2_seqnum=3
  - dat_seqnum=255, bk1_seqnum=254, bk2_seqnum=255
  - dat_seqnum=0, bk1_seqnum=255, bk2_seqnum=0
- Test case 52 dat present, 2 bak files: dat file not up to date: check new xxxx.dat created and only 1 correct bak file created.
  - dat_seqnum=2, bk1_seqnum=2, bk2_seqnum=3
  - dat_seqnum=254, bk1_seqnum=254, bk2_seqnum=255
  - dat_seqnum=255, bk1_seqnum=255, bk2_seqnum=0
- Test case 53 dat present, n bak present but files dont have matching sequence number and dat_seq > bak_seqnum. check new xxxx.bak is created
  - dat_seqnum=3, bk1_seqnum=2
  - dat_seqnum=255, bk1_seqnum=254
  - dat_seqnum=0, bk1_seqnum=255
  - dat_seqnum=1, bk1_seqnum=0
  Test case 54 dat present, 1 bak present but files dont have matching sequence number and dat_seq < bak_seqnum. check new xxxx.dat is created
  - dat_seqnum=3, bk1_seqnum=4
  - dat_seqnum=254, bk1_seqnum=255
  - dat_seqnum=255, bk1_seqnum=0
  - dat_seqnum=0, bk1_seqnum=1
- Test case 55 dat present, 0 bak present. check new xxxx.bak is created
  - dat_seqnum=2
- Test case 101  Test case 1 but uid file has \_F\_WRITE_ONCE flag set
- Test case 102  Test case 2 but uid file has \_F\_WRITE_ONCE flag set
- Test case 105  Test case 5 but uid file has \_F\_WRITE_ONCE flag set

- Test case 151  Test case 51 but uid file has \_F\_WRITE_ONCE flag set
- Test case 152  Test case 52 but uid file has \_F\_WRITE_ONCE flag set
- Test case 153  Test case 53 but uid file has \_F\_WRITE_ONCE flag set
- Test case 154  Test case 54 but uid file has \_F\_WRITE_ONCE flag set
- Test case 155  Test case 55 but uid file has \_F\_WRITE_ONCE flag set
