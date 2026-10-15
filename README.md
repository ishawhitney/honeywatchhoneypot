# HoneyWatch

## Honeypot Attack Detection and Monitoring System

HoneyWatch is a software-based honeypot monitoring and attack detection system designed to simulate suspicious activity, record security events, detect attack patterns, classify incidents, calculate threat scores, and present the results through a web-based security dashboard.

---

## Project Overview

HoneyWatch follows this processing pipeline:

```text
Honeypot / Activity Simulation
            ↓
      Activity Logger
            ↓
      SQLite Database
            ↓
     Detection Engine
            ↓
     Attack Classifier
            ↓
      Threat Scoring
            ↓
     Incident Manager
            ↓
      FastAPI Backend
            ↓
     Security Dashboard