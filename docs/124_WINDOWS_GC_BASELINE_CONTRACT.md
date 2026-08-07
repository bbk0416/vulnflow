# Windows garbage-collection baseline contract

## Problem

A process-wide equality assertion for the number of live FastAPI `APIRoute` objects assumed that all objects created by earlier tests had already been collected before the baseline was captured. Windows CPython 3.13 invalidated that assumption: delayed collection occurred during the repeated-app test, so the total decreased even though the objects created by the current test were fully released.

## Correct contract

The regression now tracks the ownership graph created by the test itself. It stores weak references to each isolated application, each of its 276 transferred `APIRoute` objects, and each route endpoint function. After lifecycle shutdown, reference deletion, and garbage collection, all tracked references must be dead.

Process-wide route and runtime-namespace counts remain secondary upper bounds only. A decrease is valid because it represents cleanup of objects created before the current test; an increase remains a failure.

## Product boundary

This change modifies tests and release metadata only. The direct isolated-route transfer introduced in 72.0.63, route count, schema 46, runtime soak thresholds, and external-validation classification are unchanged.
