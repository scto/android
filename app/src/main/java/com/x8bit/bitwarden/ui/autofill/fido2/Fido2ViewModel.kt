package com.x8bit.bitwarden.ui.autofill.fido2

import androidx.lifecycle.viewModelScope
import com.bitwarden.vault.CipherView
import com.x8bit.bitwarden.R
import com.x8bit.bitwarden.data.auth.repository.AuthRepository
import com.x8bit.bitwarden.data.auth.repository.model.UserState
import com.x8bit.bitwarden.data.autofill.fido2.manager.Fido2CredentialManager
import com.x8bit.bitwarden.data.autofill.fido2.model.Fido2GetCredentialsRequest
import com.x8bit.bitwarden.data.autofill.fido2.model.Fido2GetCredentialsResult
import com.x8bit.bitwarden.data.platform.manager.SpecialCircumstanceManager
import com.x8bit.bitwarden.data.platform.manager.util.toFido2GetCredentialsRequestOrNull
import com.x8bit.bitwarden.data.platform.repository.model.DataState
import com.x8bit.bitwarden.data.vault.repository.VaultRepository
import com.x8bit.bitwarden.data.vault.repository.model.VaultData
import com.x8bit.bitwarden.ui.platform.base.BaseViewModel
import com.x8bit.bitwarden.ui.platform.base.util.BackgroundEvent
import com.x8bit.bitwarden.ui.platform.base.util.Text
import com.x8bit.bitwarden.ui.platform.base.util.asText
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Models logic for [Fido2Screen].
 */
@Suppress("LargeClass")
@HiltViewModel
class Fido2ViewModel @Inject constructor(
    private val authRepository: AuthRepository,
    vaultRepository: VaultRepository,
    private val fido2CredentialManager: Fido2CredentialManager,
    private val specialCircumstanceManager: SpecialCircumstanceManager,
) : BaseViewModel<Fido2State, Fido2Event, Fido2Action>(
    initialState = run {
        val specialCircumstance = specialCircumstanceManager.specialCircumstance
        val fido2GetCredentialsRequest = specialCircumstance?.toFido2GetCredentialsRequestOrNull()
        val requestUserId = fido2GetCredentialsRequest?.userId
        Fido2State(
            requestUserId = requireNotNull(requestUserId),
            fido2GetCredentialsRequest = fido2GetCredentialsRequest,
            dialog = null,
        )
    },
) {

    init {
        vaultRepository.vaultDataStateFlow
            .map { Fido2Action.Internal.VaultDataStateChangeReceive(it) }
            .onEach(::trySendAction)
            .launchIn(viewModelScope)

        authRepository.userStateFlow
            .map { Fido2Action.Internal.UserStateChangeReceive(it) }
            .onEach(::trySendAction)
            .launchIn(viewModelScope)
    }

    override fun handleAction(action: Fido2Action) {
        when (action) {
            is Fido2Action.DismissErrorDialogClick -> {
                clearDialogState()
                sendEvent(
                    Fido2Event.CompleteFido2GetCredentialsRequest(
                        result = action.result,
                    ),
                )
            }

            is Fido2Action.Internal -> {
                handleInternalAction(action)
            }
        }
    }

    private fun handleInternalAction(action: Fido2Action.Internal) {
        when (action) {
            is Fido2Action.Internal.VaultDataStateChangeReceive -> {
                handleVaultDataStateChangeReceive(action.vaultData)
            }

            is Fido2Action.Internal.UserStateChangeReceive -> {
                handleUserStateChangeReceive(action)
            }
        }
    }

    private fun handleUserStateChangeReceive(action: Fido2Action.Internal.UserStateChangeReceive) {
        val activeUserId = action.userState?.activeUserId ?: return
        val requestUserId = state.requestUserId
        if (requestUserId != activeUserId) {
            authRepository.switchAccount(requestUserId)
        }
    }

    private fun handleVaultDataStateChangeReceive(vaultDataState: DataState<VaultData>) {
        when (vaultDataState) {
            is DataState.Error -> mutableStateFlow.update {
                it.copy(
                    dialog = Fido2State.DialogState.Error(
                        title = R.string.an_error_has_occurred.asText(),
                        message = R.string.generic_error_message.asText(),
                    ),
                )
            }

            is DataState.Loaded -> handleVaultDataLoaded()
            DataState.Loading -> handleVaultDataLoading()
            is DataState.NoNetwork -> handleNoNetwork()
            is DataState.Pending -> clearDialogState()
        }
    }

    private fun handleVaultDataLoaded() {
        clearDialogState()
        if (authRepository.activeUserId != state.requestUserId) {
            // Ignore vault data when we are waiting for the account to switch
            return
        }

        viewModelScope.launch {
            state
                .fido2GetCredentialsRequest
                ?.let { getCredentialsRequest ->
                    getFido2CredentialAutofillViewsForSelection(getCredentialsRequest)
                }
        }
    }

    private suspend fun getFido2CredentialAutofillViewsForSelection(
        fido2GetCredentialsRequest: Fido2GetCredentialsRequest,
    ) {
        val getCredentialsResult = fido2CredentialManager
            .getFido2CredentialsForRelyingParty(fido2GetCredentialsRequest)

        when (getCredentialsResult) {
            is Fido2GetCredentialsResult.Error -> {
                showFido2ErrorDialog(
                    title = R.string.an_error_has_occurred.asText(),
                    message = R.string.passkey_operation_failed_because_passkey_does_not_exist
                        .asText(),
                )
            }

            Fido2GetCredentialsResult.Cancelled,
            is Fido2GetCredentialsResult.Success,
                -> {
                sendEvent(
                    Fido2Event.CompleteFido2GetCredentialsRequest(
                        result = getCredentialsResult,
                    ),
                )
            }
        }

        sendEvent(
            Fido2Event.CompleteFido2GetCredentialsRequest(
                result = getCredentialsResult,
            ),
        )
    }

    private fun handleVaultDataLoading() {
        mutableStateFlow.update { it.copy(dialog = Fido2State.DialogState.Loading) }
    }

    private fun handleNoNetwork() {
        mutableStateFlow.update {
            it.copy(
                dialog = Fido2State.DialogState.Error(
                    R.string.internet_connection_required_title.asText(),
                    R.string.internet_connection_required_message.asText(),
                ),
            )
        }
    }

    private fun showFido2ErrorDialog(title: Text, message: Text) {
        mutableStateFlow.update {
            it.copy(
                dialog = Fido2State.DialogState.Error(title, message),
            )
        }
    }

    private fun clearDialogState() {
        mutableStateFlow.update { it.copy(dialog = null) }
    }
}

/**
 * Represents the UI state for [Fido2Screen].
 *
 * @property requestUserId User ID contained within the FIDO 2 request.
 * @property fido2GetCredentialsRequest Data required to discover FIDO 2 credential.
 */
data class Fido2State(
    val requestUserId: String,
    val fido2GetCredentialsRequest: Fido2GetCredentialsRequest?,
    val dialog: DialogState?,
) {

    /**
     * Represents the dialog UI state for [Fido2Screen].
     */
    sealed class DialogState {
        /**
         * Displays a loading dialog.
         */
        data object Loading : DialogState()

        /**
         * Displays a generic error dialog with a [title] and [message].
         */
        data class Error(val title: Text, val message: Text) : DialogState()

        /**
         * Displays a PIN entry dialog to verify the user.
         */
        data class Fido2PinPrompt(val selectedCipherId: String) : DialogState()

        /**
         * Displays a master password entry dialog to verify the user.
         */
        data class Fido2MasterPasswordPrompt(val selectedCipherId: String) : DialogState()

        /**
         * Displays a PIN creation dialog for user verification.
         */
        data class Fido2PinSetUpPrompt(val selectedCipherId: String) : DialogState()

        /**
         * Displays a master password validation error dialog.
         */
        data class Fido2MasterPasswordError(
            val title: Text?,
            val message: Text,
            val selectedCipherId: String,
        ) : DialogState()

        /**
         * Displays a PIN set up error dialog.
         */
        data class Fido2PinSetUpError(
            val title: Text?,
            val message: Text,
            val selectedCipherId: String,
        ) : DialogState()

        /**
         * Displays a PIN validation error dialog.
         */
        data class Fido2PinError(
            val title: Text?,
            val message: Text,
            val selectedCipherId: String,
        ) : DialogState()
    }
}

/**
 * Models events for [Fido2Screen].
 */
sealed class Fido2Event {

    /**
     * Completes FIDO 2 credential discovery with the given [result].
     */
    data class CompleteFido2GetCredentialsRequest(
        val result: Fido2GetCredentialsResult,
    ) : BackgroundEvent, Fido2Event()

    /**
     * Performs device based user verification.
     */
    data class Fido2UserVerification(
        val required: Boolean,
        val selectedCipher: CipherView,
    ) : BackgroundEvent, Fido2Event()
}

/**
 * Models actions for [Fido2Screen].
 */
sealed class Fido2Action {

    /**
     * Indicates the user dismissed the error dialog.
     */
    data class DismissErrorDialogClick(val result: Fido2GetCredentialsResult) : Fido2Action()

    /**
     * Models actions [Fido2ViewModel] may itself send.
     */
    sealed class Internal : Fido2Action() {

        /**
         * Indicates the [userState] has changed.
         */
        data class UserStateChangeReceive(
            val userState: UserState?,
        ) : Internal()

        /**
         * Indicates the [vaultData] has changed.
         */
        data class VaultDataStateChangeReceive(
            val vaultData: DataState<VaultData>,
        ) : Internal()
    }
}
