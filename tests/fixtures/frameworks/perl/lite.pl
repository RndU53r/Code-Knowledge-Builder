#!/usr/bin/perl
use Mojolicious::Lite;
use Dancer2;

post '/orders' => sub ($c) {
    my $item = $c->param('item');
    system("ship $item");
    $c->render(text => 'ok');
};

get '/items' => sub { return 'items' };

app->start;
