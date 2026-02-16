# Anisakys Performance Profiling Report

**Date**: 2026-01-03 23:24:17
**Sprint**: 5 - Performance Optimization

---

## Executive Summary

| Service | Operation | Time (seconds) | Status |
|---------|-----------|----------------|--------|
| typosquatting | generate variants | 0.278s | ✅ Good |
| ct | monitor keywords | 1.519s | ⚠️ Needs Optimization |
| collaboration | assign case | 0.117s | ✅ Good |

---

## Detailed Profiling Results

### typosquatting_generate_variants

**Elapsed Time**: 0.278 seconds

**Top 20 Functions by Cumulative Time:**

```
         191 function calls in 0.236 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.066    0.066    0.171    0.171 /opt/bmad/anisakys/src/services/typosquatting_service.py:103(generate_variants)
        1    0.065    0.065    0.065    0.065 {method 'disable' of '_lsprof.Profiler' objects}
        1    0.000    0.000    0.045    0.045 /usr/local/lib/python3.13/logging/__init__.py:1509(info)
        1    0.045    0.045    0.045    0.045 /usr/local/lib/python3.13/logging/__init__.py:1764(isEnabledFor)
        1    0.019    0.019    0.019    0.019 /opt/bmad/anisakys/src/services/typosquatting_service.py:187(_generate_homoglyphs)
        1    0.016    0.016    0.016    0.016 {method 'lower' of 'str' objects}
       46    0.009    0.000    0.009    0.000 {built-in method builtins.len}
       44    0.008    0.000    0.008    0.000 {method 'add' of 'set' objects}
        1    0.008    0.008    0.008    0.008 {method 'split' of 'str' objects}
        1    0.000    0.000    0.000    0.000 /opt/bmad/anisakys/src/services/typosquatting_service.py:197(_generate_typos)
       88    0.000    0.000    0.000    0.000 {method 'append' of 'list' objects}
        1    0.000    0.000    0.000    0.000 {method 'replace' of 'str' objects}
        1    0.000    0.000    0.000    0.000 {method 'join' of 'str' objects}
        1    0.000    0.000    0.000    0.000 {method '__exit__' of '_thread.RLock' objects}
        1    0.000    0.000    0.000    0.000 /usr/local/lib/python3.13/logging/__init__.py:1750(getEffectiveLevel)
        1    0.000    0.000    0.000    0.000 /usr/local/lib/python3.13/logging/__init__.py:1353(disable)


```

---

### ct_monitor_keywords

**Elapsed Time**: 1.519 seconds

**Top 20 Functions by Cumulative Time:**

```
         4547 function calls (4545 primitive calls) in 1.519 seconds

   Ordered by: cumulative time
   List reduced from 95 to 20 due to restriction <20>

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        6    0.000    0.000    1.505    0.251 /usr/local/lib/python3.13/asyncio/base_events.py:1953(_run_once)
        6    0.001    0.000    1.502    0.250 /usr/local/lib/python3.13/selectors.py:435(select)
        6    1.501    0.250    1.501    0.250 {method 'poll' of 'select.epoll' objects}
        4    0.000    0.000    0.017    0.004 /opt/bmad/anisakys/src/services/ct_monitor_service.py:295(monitor_keywords)
      150    0.011    0.000    0.012    0.000 /opt/bmad/anisakys/src/services/ct_monitor_service.py:115(parse_certificate)
        6    0.000    0.000    0.002    0.000 /usr/local/lib/python3.13/asyncio/events.py:87(_run)
        6    0.000    0.000    0.002    0.000 {method 'run' of '_contextvars.Context' objects}
        6    0.001    0.000    0.002    0.000 /usr/local/lib/python3.13/asyncio/tasks.py:703(sleep)
        3    0.000    0.000    0.002    0.001 /opt/bmad/anisakys/scripts/performance_profiling.py:268(main)
        3    0.000    0.000    0.002    0.001 /opt/bmad/anisakys/scripts/performance_profiling.py:227(run_all_profiles)
        3    0.000    0.000    0.002    0.001 /opt/bmad/anisakys/scripts/performance_profiling.py:99(profile_ct_monitor_service)
        3    0.000    0.000    0.002    0.001 /opt/bmad/anisakys/scripts/performance_profiling.py:57(profile_async_function)
        3    0.000    0.000    0.001    0.000 /usr/local/lib/python3.13/asyncio/base_events.py:776(call_later)
        3    0.001    0.000    0.001    0.000 /usr/local/lib/python3.13/asyncio/base_events.py:800(call_at)
        3    0.000    0.000    0.001    0.000 /opt/bmad/anisakys/src/services/ct_monitor_service.py:72(search_crt_sh)
        9    0.000    0.000    0.001    0.000 /usr/local/lib/python3.13/unittest/mock.py:1162(__call__)
      150    0.001    0.000    0.001    0.000 {built-in method fromisoformat}
        9    0.000    0.000    0.001    0.000 /usr/local/lib/python3.13/unittest/mock.py:1173(_increment_mock_call)
      150    0.000    0.000    0.001    0.000 /opt/bmad/anisakys/src/services/ct_monitor_service.py:162(calculate_threat_score)
        9    0.000    0.000    0.000    0.000 /usr/local/lib/python3.13/unittest/mock.py:1170(_mock_call)


```

---

### collaboration_assign_case

**Elapsed Time**: 0.117 seconds

**Top 20 Functions by Cumulative Time:**

```
         72368 function calls (69213 primitive calls) in 0.117 seconds

   Ordered by: cumulative time
   List reduced from 510 to 20 due to restriction <20>

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.000    0.000    0.117    0.117 /opt/bmad/anisakys/src/services/collaboration_service.py:50(assign_case)
        1    0.000    0.000    0.116    0.116 <string>:1(__init__)
        1    0.000    0.000    0.116    0.116 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/state.py:587(_initialize_instance)
        1    0.000    0.000    0.116    0.116 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/event/attr.py:509(__call__)
        1    0.000    0.000    0.116    0.116 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/mapper.py:4408(_event_on_init)
     13/1    0.000    0.000    0.116    0.116 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/mapper.py:2402(_check_configure)
     13/1    0.000    0.000    0.116    0.116 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/mapper.py:4199(_configure_registries)
        1    0.000    0.000    0.115    0.115 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/mapper.py:4233(_do_configure_registries)
       12    0.001    0.000    0.115    0.010 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/mapper.py:2412(_post_configure_properties)
      208    0.000    0.000    0.074    0.000 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/interfaces.py:587(init)
       34    0.007    0.000    0.071    0.002 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/relationships.py:1652(do_init)
       34    0.000    0.000    0.044    0.001 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/relationships.py:1894(_setup_join_conditions)
       34    0.000    0.000    0.043    0.001 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/relationships.py:2284(__init__)
      208    0.000    0.000    0.040    0.000 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/interfaces.py:1114(post_instrument_class)
      208    0.002    0.000    0.038    0.000 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/strategies.py:70(_register_attribute)
      208    0.001    0.000    0.021    0.000 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/attributes.py:2595(register_attribute_impl)
      174    0.001    0.000    0.020    0.000 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/strategies.py:240(init_class_attribute)
       34    0.000    0.000    0.019    0.001 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/orm/strategies.py:768(init_class_attribute)
3420/1912    0.003    0.000    0.018    0.000 {built-in method builtins.hasattr}
  948/774    0.003    0.000    0.018    0.000 /opt/bmad/anisakys/venv/lib/python3.13/site-packages/sqlalchemy/util/langhelpers.py:1387(__getattr__)


```

---

## Optimization Recommendations

### 🔴 Operations Requiring Optimization

**ct_monitor_keywords** (1.519s):
- Analyze function calls in profiler output
- Look for opportunities to:
  - Cache results
  - Optimize algorithms
  - Reduce I/O operations
  - Use async/await properly

---

## Next Steps

1. ✅ Review profiling results
2. Implement caching for frequently accessed data
3. Optimize identified bottlenecks
4. Run load testing with Locust
5. Profile database queries with SQLAlchemy logging
6. Implement connection pooling
7. Re-profile after optimizations

