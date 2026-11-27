package Shop::OrderRepo;
use strict;
use parent -norequire, 'Shop::BaseRepo';
use DBI;

sub save {
    my ($self, $item) = @_;
    my $dbh = DBI->connect('dbi:Pg:dbname=shop');
    $dbh->do("INSERT INTO orders (item) VALUES ('$item')");
    return $item;
}

1;
