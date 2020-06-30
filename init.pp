more init.pp
class stigs (
  $grub_password         = undef,
  $pam_auth_template     = 'stigs/system-auth-ac.erb',
  $pam_password_template = 'stigs/password-auth-ac.erb',
  $pam_enablesssd        = false,
  $pam_enablekrb5        = false,
  $pam_enableldap        = false,
  $pam_mkhomedir         = false,
  $enable_autofs         = false,
  $remote_syslog         = 'logger.service.consul',
  $audisp_remote_config  = { remote_server => 'logger.service.consul' },
) {

  # validate input parameters
  #validate_re($grub_password, '^\$.+$')
  validate_bool($enable_autofs)


  include selinux
  include firewall


  # Setup the firewall configuration
  resources { "firewall":
    purge => true
  }
  Firewall {
    before => Class['::stigs::firewall::post'],
    require => Class['::stigs::firewall::pre'],
  }

  anchor { 'stigs::begin': } ->
  class { ['::stigs::firewall::pre', '::stigs::firewall::post']: } ->

  class { ::stigs::pam:
    pam_auth_template     => $pam_auth_template,
    pam_password_template => $pam_password_template,
    pam_enablesssd        => $pam_enablesssd,
    pam_enablekrb5        => $pam_enablekrb5,
    pam_enableldap        => $pam_enableldap,
    pam_mkhomedir         => $pam_mkhomedir,
  } ->

  class { ::stigs::rules::srg_os_999999: autofs => $enable_autofs } ->
  class { ::stigs::rules::srg_os_000080: password => $grub_password } ->
  class { ::stigs::rules::srg_os_000215: remote_syslog => $remote_syslog } ->

  # rhel-06-000227 srg_os_000112
  # rhel-06-000239 srg_os_000106
  # rhel-06-000234 srg_os_000106
  # rhel-06-000236 srg_os_000106
  # rhel-06-000237 srg_os_000109
  # rhel-06-000240 srg_os_000023
  # rhel-06-000230 srg_os_000163
  # rhel-06-000230 srg_os_000163
  # rhel-06-000231 srg_os_000126
  # rhel-06-000241 srg_os_000242
  class { ssh:
    permit_root_login                 => 'no',
    sshd_config_permituserenvironment => 'no',
    sshd_config_banner                => '/etc/issue',
    sshd_client_alive_count_max       => '0',
    sshd_config_ciphers               => ['aes128-ctr,aes192-ctr,aes256-ctr'],
    sshd_config_macs                  => ['hmac-sha1'],
  } ->
  anchor { 'stigs::end': }

  contain ::stigs::rules::srg_os_000056
  contain ::stigs::rules::srg_os_000095
  contain ::stigs::rules::srg_os_000109
  contain ::stigs::rules::srg_os_000232
  contain ::stigs::rules::srg_os_000248
  contain ::stigs::rules::srg_os_000259
  contain ::stigs::rules::srg_os_000142
  contain ::stigs::rules::srg_os_000120
  contain ::stigs::rules::srg_os_000078
  contain ::stigs::rules::srg_os_000075
  contain ::stigs::rules::srg_os_000076
  contain ::stigs::rules::srg_os_000096
  contain ::stigs::rules::srg_os_000034
  contain ::stigs::rules::srg_os_000103
  contain ::stigs::rules::srg_os_999999
  contain ::stigs::rules::srg_os_000080
  contain ::stigs::rules::srg_os_000215

  # rhel-06-000159 srg_os_999999
  # rhel-06-000160 srg_os_999999
  # rhel-06-000161 srg_os_999999
  # rhel-06-000202 srg_os_000064
  # rhel-06-000313 srg_os_000046
  # rhel-06-000165 srg_os_000062
  # rhel-06-000173 srg_os_000062
  # rhel-06-000174 srg_os_000004
  # rhel-06-000175 srg_os_000239
  # rhel-06-000176 srg_os_000240
  # rhel-06-000177 srg_os_000241
  # rhel-06-000183 srg_os_999999
  # rhel-06-000184 srg_os_000064
  # rhel-06-000185 srg_os_000064
  # rhel-06-000186 srg_os_000064
  # rhel-06-000187 srg_os_000064
  # rhel-06-000188 srg_os_000064
  # rhel-06-000189 srg_os_000064
  # rhel-06-000190 srg_os_000064
  # rhel-06-000191 srg_os_000064
  # rhel-06-000192 srg_os_000064
  # rhel-06-000193 srg_os_000064
  # rhel-06-000194 srg_os_000064
  # rhel-06-000195 srg_os_000064
  # rhel-06-000196 srg_os_000064
  # rhel-06-000200 srg_os_000064
  class { ::auditd:
    max_log_file            => 100,
    admin_space_left        => 85,
    admin_space_left_action => 'single',
    disk_full_action        => 'single',
    disk_error_action       => 'single',
    space_left              => 125,
    audisp_q_depth          => 2048,
    audisp_name_format      => 'hostname',
  }

  $config_defaults = {
    remote_server   => 'audit',
    port            => 601,
    transport       => 'tcp',
    queue_file      => '/var/spool/audit/remote.log',
    mode            => 'immediate',
    queue_depth     => 2048,
    format          => 'ascii',
    overflow_action => 'ignore',
  }

  $config = merge($config_defaults, $audisp_remote_config)

  file { "/etc/audisp/audisp-remote.conf":
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0640',
    content => template("${module_name}/audisp-remote.conf.erb"),
    notify  => Service['auditd'],
  }

  exec { 'audisp-remote-check':
    path    => ['/bin', '/sbin'],
    command => 'service auditd restart',
    unless  => 'ps -ef | grep audisp-remote | grep -v grep',
  }

  # audit_time_rules
  #RHEL-06-000165
  #RHEL-06-000167
  #RHEL-06-000171
  #RHEL-06-000173
  auditd::rule { '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules': }
  auditd::rule { '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules': }
  auditd::rule { '-w /etc/localtime -p wa -k audit_time_rules': }


  # audit_account_changes
  #RHEL-06-000174
  #RHEL-06-000175
  #RHEL-06-000176
  #RHEL-06-000177
  #RHEL-06-000182
  auditd::rule { '-w /etc/group -p wa -k audit_account_changes': }
  auditd::rule { '-w /etc/passwd -p wa -k audit_account_changes': }
  auditd::rule { '-w /etc/gshadow -p wa -k audit_account_changes': }
  auditd::rule { '-w /etc/shadow -p wa -k audit_account_changes': }
  auditd::rule { '-w /etc/security/opasswd -p wa -k audit_account_changes': }


  # audit_network_modifications
  #RHEL-06-000182
  auditd::rule { '-a exit,always -F arch=b32 -S sethostname -S setdomainname -k audit_network_modifications': }
  auditd::rule { '-a exit,always -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications': }
  auditd::rule { '-w /etc/issue -p wa -k audit_network_modifications': }
  auditd::rule { '-w /etc/issue.net -p wa -k audit_network_modifications': }
  auditd::rule { '-w /etc/hosts -p wa -k audit_network_modifications': }
  auditd::rule { '-w /etc/sysconfig/network -p wa -k audit_network_modifications': }


  #audit_mac_configuration
  #RHEL-06-000183
  auditd::rule { '-w /etc/selinux/ -p wa -k MAC-policy': }


  # audit_dac_changes
  #RHEL-06-000184
  auditd::rule { '-a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b32 -S chmod -F auid=0 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S chmod -F auid=0 -k perm_mod': }

  #RHEL-06-000185
  auditd::rule { '-a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b32 -S chown -F auid=0 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S chown -F auid=0 -k perm_mod': }

  #RHEL-06-000186
  auditd::rule { '-a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b32 -S fchmod -F auid=0 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S fchmod -F auid=0 -k perm_mod': }

  #RHEL-06-000187
  auditd::rule { '-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b32 -S fchmodat -F auid=0 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S fchmodat -F auid=0 -k perm_mod': }

  #RHEL-06-000188
  auditd::rule { '-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b32 -S fchown -F auid=0 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S fchown -F auid=0 -k perm_mod': }

  #RHEL-06-000189
  auditd::rule { '-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b32 -S fchownat -F auid=0 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S fchownat -F auid=0 -k perm_mod': }

  #RHEL-06-000190
  auditd::rule { '-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b32 -S fremovexattr -F auid=0 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -k perm_mod': }

  #RHEL-06-000191
  auditd::rule { '-a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod': }

  #RHEL-06-000192
  auditd::rule { '-a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b32 -S lchown -F auid=0 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S lchown -F auid=0 -k perm_mod': }

  #RHEL-06-000193
  auditd::rule { '-a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -k perm_mod': }

  #RHEL-06-000194
  auditd::rule { '-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -k perm_mod': }

  #RHEL-06-000195
  auditd::rule { '-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b32 -S removexattr -F auid=0 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod': }
  auditd::rule { '-a always,exit -F arch=b64 -S removexattr -F auid=0 -k perm_mod': }

  #RHEL-06-000196
  auditd::rule { '-a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod ': }
  auditd::rule { '-a always,exit -F arch=b32 -S setxattr -F auid=0 -k perm_mod ': }
  auditd::rule { '-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod ': }
  auditd::rule { '-a always,exit -F arch=b64 -S setxattr -F auid=0 -k perm_mod ': }

  #RHEL-06-000197
  auditd::rule { '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F aui
d!=4294967295 -k access': }
  auditd::rule { '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid
!=4294967295 -k access': }
  auditd::rule { '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid=0 -k access
': }
  auditd::rule { '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid=0 -k access 
  ': }


  # audit_setuid_usage
  #RHEL-06-000198
  auditd::rule { '-a always,exit -F path=/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k privi
leged': }
  auditd::rule { '-a always,exit -F path=/bin/cgexec -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/bin/su -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/bin/ping6 -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/bin/mount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/bin/umount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/bin/ping -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/bin/cgclassify -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/screen -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/locate -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/staprun -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged':
 }
  auditd::rule { '-a always,exit -F path=/usr/libexec/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=500 -F auid!=4294967295 -k p
rivileged': }
  auditd::rule { '-a always,exit -F path=/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper -F perm=x -F auid>=500 -F auid!=429496
7295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper -F perm=x -F auid>=500 -F auid!=429496
7295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/sbin/mount.nfs -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/sbin/netreport -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }
  auditd::rule { '-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged': }


  # audit_mount_events
  #RHEL-06-000199
  auditd::rule { '-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export': }
  auditd::rule { '-a always,exit -F arch=b64 -S mount -F auid=0 -k export': }


  # audit_file_deletion
  #RHEL-06-000200
  auditd::rule { '-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -
k delete': }
  auditd::rule { '-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete': }


  # audit_sudoer_changes
  #RHEL-06-000201
  auditd::rule { '-w /etc/sudoers -p wa -k actions': }


  # audit_kernel_loading
  #RHEL-06-000202
  auditd::rule { '-w /sbin/insmod -p x -k modules': }
  auditd::rule { '-w /sbin/rmmod -p x -k modules': }
  auditd::rule { '-w /sbin/modprobe -p x -k modules': }
  auditd::rule { '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules': }


  include ::auditd
  include ::auditd::audisp::au_remote

  contain ::stigs::banner
}
