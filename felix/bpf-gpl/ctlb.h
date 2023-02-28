#ifndef _CTLB_H_
#define _CTLB_H_

const volatile struct cali_ctlb_globals __globals;
#define CTLB_UDP_NOT_SEEN_TIMEO __globals.udp_not_seen_timeo
#define CTLB_EXCLUDE_UDP __globals.exclude_udp

#endif /* _CTLB_H_ */
