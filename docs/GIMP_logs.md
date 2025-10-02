# Анализ Valgrind логов GIMP - GIF Loader (libgif)

## Обзор

Valgrind анализ был проведен для GIMP 2.10.34 при загрузке 50 краш-файлов GIF. Команда запуска:

```bash
G_DEBUG=gc-friendly G_SLICE=always-malloc valgrind   --leak-check=full   --show-leak-kinds=all   --track-origins=yes   --num-callers=40   --log-file=valgrind_multi.log   gimp-console --no-interface     $(for i in $(seq 1 50); do \
        echo -n "-b '(gimp-file-load RUN-NONINTERACTIVE \"poc_copies/poc_${i}.gif\" \"poc_copies/poc_${i}.gif\")' "; \
      done)     -b '(gimp-quit 0)'
```

## GIF Loader (libgif) - специфичные утечки

### 1. GIF Loader Class Initialization

```
==222447== 1 bytes in 1 blocks are still reachable in loss record 13 of 32,742
==222447==    at 0x48417B4: malloc (vg_replace_malloc.c:381)
==222447==    by 0x52CE5D8: g_malloc (gmem.c:130)
==222447==    by 0x52E8BDE: g_strdup (gstrfuncs.c:363)
==222447==    by 0x4D7658D: gegl_param_spec_file_path (gegl-paramspecs.c:418)
==222447==    by 0xE5E9E43: gegl_op_class_intern_init (gif-load.c:34)
==222447==    by 0xE5E9E43: gegl_op_gif_load_class_chant_intern_init (gegl-op.h:212)
==222447==    by 0x524B00A: type_class_init_Wm (gtype.c:2299)
==222447==    by 0x524B00A: g_type_class_ref (gtype.c:3014)
==222447==    by 0x4D70855: add_operations (gegl-operations.c:140)
==222447==    by 0x4D70866: add_operations (gegl-operations.c:142)
==222447==    by 0x4D70ABC: gegl_operation_gtype_from_name (gegl-operations.c:287)
==222447==    by 0x4D70ABC: gegl_operation_gtype_from_name (gegl-operations.c:270)
==222447==    by 0x4D70B18: gegl_has_operation (gegl-operations.c:311)
==222447==    by 0x15FBDB: sanity_check_gegl_ops (sanity.c:725)
==222447==    by 0x15FBDB: sanity_check_late (sanity.c:116)
==222447==    by 0x15EB7F: app_run (app.c:301)
==222447==    by 0x15E695: main (main.c:656)
```

- **Размер**: 1 byte
- **Источник**: GEGL GIF loader class initialization (gif-load.c:34)

### 2. GIF Loader Module Type Registration

```
==222447== 16 bytes in 1 blocks are still reachable in loss record 3,539 of 32,742
==222447==    at 0x48416C4: malloc (vg_replace_malloc.c:380)
==222447==    by 0x52CE677: g_realloc (gmem.c:201)
==222447==    by 0x52489FC: type_set_qdata_W (gtype.c:3803)
==222447==    by 0x52489FC: type_add_flags_W (gtype.c:3854)
==222447==    by 0x524E478: g_type_register_dynamic (gtype.c:2878)
==222447==    by 0x525098A: g_type_module_register_type (gtypemodule.c:437)
==222447==    by 0xE5E815C: ??? (in /usr/lib/x86_64-linux-gnu/gegl-0.4/gif-load.so)
==222447==    by 0xE5DC048: gegl_op_class_intern_init (convert-space.c:27)
==222447==    by 0xE5DC048: gegl_op_convert_space_class_chant_intern_init (gegl-op.h:212)
==222447==    by 0x4D620C2: gegl_module_load (geglmodule.c:142)
==222447==    by 0x4D6234A: gegl_module_new (geglmodule.c:204)
==222447==    by 0x4D62A7B: gegl_module_db_load (geglmoduledb.c:303)
==222447==    by 0x52E8707: g_slist_foreach (gslist.c:887)
==222447==    by 0x4D10187: gegl_post_parse_hook (gegl-init.c:641)
==222447==    by 0x52D5FE0: g_option_context_parse (goption.c:2219)
==222447==    by 0x52D6F24: g_option_context_parse_strv (goption.c:2759)
==222447==    by 0x15E5AF: main (main.c:605)
```

- **Размер**: 16 bytes
- **Источник**: GEGL GIF loader module type registration

### 3. GIF Loader Module Initialization

```
==222447== 16 bytes in 1 blocks are still reachable in loss record 3,538 of 32,742
==222447==    at 0x48465EF: calloc (vg_replace_malloc.c:1328)
==222447==    by 0x52CE630: g_malloc0 (gmem.c:163)
==222447==    by 0x5248A76: type_set_qdata_W (gtype.c:3789)
==222447==    by 0x5248A76: type_add_flags_W (gtype.c:3854)
==222447==    by 0x524E478: g_type_register_dynamic (gtype.c:2878)
==222447==    by 0x525098A: g_type_module_register_type (gtypemodule.c:437)
==222447==    by 0xE5E815C: ??? (in /usr/lib/x86_64-linux-gnu/gegl-0.4/gif-load.so)
==222447==    by 0xE5DC048: gegl_op_class_intern_init (convert-space.c:27)
==222447==    by 0xE5DC048: gegl_op_convert_space_class_chant_intern_init (gegl-op.h:212)
==222447==    by 0x4D620C2: gegl_module_load (geglmodule.c:142)
==222447==    by 0x4D6234A: gegl_module_new (geglmodule.c:204)
==222447==    by 0x4D62A7B: gegl_module_db_load (geglmoduledb.c:303)
==222447==    by 0x52E8707: g_slist_foreach (gslist.c:887)
==222447==    by 0x4D10187: gegl_post_parse_hook (gegl-init.c:641)
==222447==    by 0x52D5FE0: g_option_context_parse (goption.c:2219)
==222447==    by 0x52D6F24: g_option_context_parse_strv (goption.c:2759)
==222447==    by 0x15E5AF: main (main.c:605)
```

- **Размер**: 16 bytes
- **Источник**: GEGL GIF loader module initialization

## Заключение

**GIF Loader (libgif) утечки в Valgrind:**
- **Общий объем**: ~33 bytes (1 + 16 + 16 bytes)
- **Тип**: still reachable (память остается доступной)
- **Источник**: инициализация GEGL GIF loader модуля

