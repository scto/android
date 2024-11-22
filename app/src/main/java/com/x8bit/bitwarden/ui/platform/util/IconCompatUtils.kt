package com.x8bit.bitwarden.ui.platform.util

import android.content.Context
import androidx.annotation.DrawableRes
import androidx.core.graphics.drawable.IconCompat
import com.bumptech.glide.Glide
import com.x8bit.bitwarden.ui.platform.components.model.IconData
import timber.log.Timber
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutionException

/**
 * Creates an IconCompat from an IconData, or falls back to a default resource if IconData is null
 * or is not of type Network.
 *
 * @param context The context to use.
 * @param iconData The IconData to create the IconCompat from.
 * @param defaultResourceId The resource ID of the default icon to use if IconData is null or not of
 * type Network.
 * @return An IconCompat created from the IconData or the default resource.
 */
fun createFido2IconCompatFromIconDataOrDefault(
    context: Context,
    iconData: IconData?,
    @DrawableRes defaultResourceId: Int,
): IconCompat = if (iconData != null && iconData is IconData.Network) {
    createFido2IconCompatFromRemoteUriOrDefaultResource(
        context = context,
        uri = iconData.uri,
        defaultResourceId = defaultResourceId,
    )
} else {
    createFido2IconCompatFromResource(context, defaultResourceId)
}

/**
 * Creates an IconCompat from a drawable resource ID.
 */
fun createFido2IconCompatFromResource(context: Context, @DrawableRes resourceId: Int) =
    IconCompat.createWithResource(context, resourceId)

private fun createFido2IconCompatFromRemoteUriOrDefaultResource(
    context: Context,
    uri: String,
    @DrawableRes defaultResourceId: Int,
): IconCompat {
    val futureTargetBitmap = Glide
        .with(context)
        .asBitmap()
        .load(uri)
        .placeholder(defaultResourceId)
        .submit()
    return try {
        IconCompat.createWithBitmap(futureTargetBitmap.get())
    } catch (e: CancellationException) {
        Timber.e(e, "Cancellation exception while loading icon.")
        IconCompat.createWithResource(context, defaultResourceId)
    } catch (e: ExecutionException) {
        Timber.e(e, "Execution exception while loading icon.")
        IconCompat.createWithResource(context, defaultResourceId)
    } catch (e: InterruptedException) {
        Timber.e(e, "Interrupted while loading icon.")
        IconCompat.createWithResource(context, defaultResourceId)
    }
}
