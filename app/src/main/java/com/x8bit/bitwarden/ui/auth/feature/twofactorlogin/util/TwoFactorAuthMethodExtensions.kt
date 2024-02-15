package com.x8bit.bitwarden.ui.auth.feature.twofactorlogin.util

import com.x8bit.bitwarden.R
import com.x8bit.bitwarden.data.auth.datasource.network.model.TwoFactorAuthMethod
import com.x8bit.bitwarden.ui.platform.base.util.Text
import com.x8bit.bitwarden.ui.platform.base.util.asText

/**
 * Get the title for the given auth method.
 */
val TwoFactorAuthMethod.title: Text
    get() = when (this) {
        TwoFactorAuthMethod.AUTHENTICATOR_APP -> R.string.authenticator_app_title.asText()
        TwoFactorAuthMethod.EMAIL -> R.string.email.asText()
        TwoFactorAuthMethod.RECOVERY_CODE -> R.string.recovery_code_title.asText()
        TwoFactorAuthMethod.YUBI_KEY -> R.string.yubi_key_title.asText()
        else -> "".asText()
    }

/**
 * Get the description for the given auth method.
 */
fun TwoFactorAuthMethod.description(email: String): Text = when (this) {
    TwoFactorAuthMethod.AUTHENTICATOR_APP -> R.string.enter_verification_code_app.asText()
    TwoFactorAuthMethod.EMAIL -> R.string.enter_verification_code_email.asText(email)
    TwoFactorAuthMethod.YUBI_KEY -> R.string.yubi_key_instruction.asText()
    else -> "".asText()
}
