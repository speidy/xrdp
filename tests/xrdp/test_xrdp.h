/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Idan Freiberg 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TEST_XRDP_H
#define TEST_XRDP_H

#include <check.h>

Suite *make_suite_test_bitmap_load(void);
Suite *make_suite_test_keymap_load(void);
Suite *make_suite_egfx_base_functions(void);
Suite *make_suite_region(void);
Suite *make_suite_tconfig_load_gfx(void);

Suite *make_suite_login(void);
#endif /* TEST_XRDP_H */
