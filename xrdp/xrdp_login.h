/* Shared data operations for the legacy and LVGL login screens. */
#ifndef XRDP_LOGIN_H
#define XRDP_LOGIN_H

struct xrdp_wm;
struct xrdp_mod_data;
struct list;
int xrdp_login_load_modules(struct xrdp_wm *, struct list *, struct list *);
int xrdp_login_parse_domain(char *, int, int, char *, unsigned int);
int xrdp_login_get_field(struct xrdp_wm *, struct xrdp_mod_data *, int, int, char [256]);
int xrdp_login_set_value(struct xrdp_mod_data *, const char *, const char *);
int xrdp_login_is_secret(const char *);
void xrdp_login_submit(struct xrdp_wm *, struct xrdp_mod_data *);
void xrdp_login_free_modules(struct list *);
#endif
