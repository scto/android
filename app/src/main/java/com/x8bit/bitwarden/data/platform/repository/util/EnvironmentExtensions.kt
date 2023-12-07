package com.x8bit.bitwarden.data.platform.repository.util

import com.x8bit.bitwarden.data.auth.datasource.disk.model.EnvironmentUrlDataJson
import com.x8bit.bitwarden.data.platform.repository.model.Environment

/**
 * Converts a raw [EnvironmentUrlDataJson] to an externally-consumable [Environment].
 */
fun EnvironmentUrlDataJson.toEnvironmentUrls(): Environment =
    when (this) {
        Environment.Us.environmentUrlData -> Environment.Us
        Environment.Eu.environmentUrlData -> Environment.Eu
        else -> Environment.SelfHosted(environmentUrlData = this)
    }

/**
 * Converts a nullable [EnvironmentUrlDataJson] to an [Environment], where `null` values default to
 * the US environment.
 */
fun EnvironmentUrlDataJson?.toEnvironmentUrlsOrDefault(): Environment =
    this?.toEnvironmentUrls() ?: Environment.Us
