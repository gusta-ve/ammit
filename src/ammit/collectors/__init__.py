"""Artifact collectors, one module per category.

Each collector is read-only and records what it gathered into the case manifest.
Collection order follows the order of volatility: volatile state first, then
persistence, accounts, filesystem and logs.
"""
