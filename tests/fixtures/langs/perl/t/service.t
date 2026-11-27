use strict;
use Test::More;
use Shop::OrderService;

my $svc = Shop::OrderService->new;
is($svc->place('book'), 'book');
done_testing;
