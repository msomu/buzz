import 'package:buzz/shared/push/android_push_banner.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('banner text comes from the fetched event, not FCM data', () {
    final banner = BuzzFetchedEventBanner.fromFetchedEvent(
      eventId: 'ab' * 32,
      communityId: 'community-1',
      channelId: 'channel-1',
      content: 'hello from the relay',
      authorName: 'Tony',
      fcmData: const {
        'title': 'payload title',
        'body': 'payload body',
        'buzz': 'reconnect',
      },
    );

    expect(banner, isNotNull);
    expect(banner!.title, 'Tony');
    expect(banner.body, 'hello from the relay');
    expect(banner.eventId, 'ab' * 32);
    expect(banner.body, isNot(contains('payload')));
    expect(banner.title, isNot(contains('payload')));
  });

  test('empty fetched content produces no banner', () {
    expect(
      BuzzFetchedEventBanner.fromFetchedEvent(
        eventId: 'ab' * 32,
        communityId: 'community-1',
        channelId: 'channel-1',
        content: '   ',
        fcmData: const {'body': 'should stay unused'},
      ),
      isNull,
    );
  });
}
