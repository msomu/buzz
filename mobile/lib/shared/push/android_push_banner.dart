/// Local Android banner built from a fetched Nostr event.
///
/// NIP-PL FCM is a reconnect constant. Title and body MUST come from the
/// event the client fetched after wake, never from FCM `data`.
class BuzzFetchedEventBanner {
  static const maxBodyChars = 180;

  final String title;
  final String body;
  final String eventId;
  final String communityId;
  final String channelId;

  const BuzzFetchedEventBanner({
    required this.title,
    required this.body,
    required this.eventId,
    required this.communityId,
    required this.channelId,
  });

  /// [fcmData] is accepted only so callers cannot accidentally treat the
  /// payload as a source. It is ignored.
  static BuzzFetchedEventBanner? fromFetchedEvent({
    required String eventId,
    required String communityId,
    required String channelId,
    required String content,
    String? authorName,
    Map<String, String>? fcmData,
  }) {
    // FCM data is a reconnect constant. Never copy it into the banner.
    final _ = fcmData;
    if (eventId.isEmpty || communityId.isEmpty || channelId.isEmpty) {
      return null;
    }
    final body = content.trim();
    if (body.isEmpty) return null;
    final clipped = body.length > maxBodyChars
        ? '${body.substring(0, maxBodyChars)}…'
        : body;
    final title = authorName == null || authorName.trim().isEmpty
        ? 'Buzz'
        : authorName.trim();
    return BuzzFetchedEventBanner(
      title: title,
      body: clipped,
      eventId: eventId,
      communityId: communityId,
      channelId: channelId,
    );
  }
}
