package Shop::OrderService;
use strict;
use warnings;
use LWP::UserAgent;
use Shop::OrderRepo;

sub new {
    my ($class) = @_;
    return bless { repo => Shop::OrderRepo->new }, $class;
}

sub place {
    my ($self, $item) = @_;
    my $ua = LWP::UserAgent->new;
    $ua->get('http://billing/charge');
    return $self->{repo}->save($item);
}

1;
