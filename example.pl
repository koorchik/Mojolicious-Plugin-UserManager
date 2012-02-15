use Mojolicious::Lite;

sub startup {
    
}

  plugin 'UM';  ## UserManager

  my $hashptr_to_schema = {
      Usermanager::Load({
             storagefile => '/var/tmp/userinfo.json',
             websitename => 'http://localhost:3000',
             captcha => 0, ## not yet implemented
             emailconfirm => 1,
             adminconfirm => 'ivo.welch@gmail.com', ## not yet implemented

             passwordmangler => q/sub { return "+$_[0]+"; }/, ## illustration.  should use md5.  json can store text, but not subs
             fields => {
                ## the first field determines the sort order in the html forms (e.g., request to register)
                ## the other fields are self-explanatory.
                ## qr// cannot be stored in json, so we must use q//

                _uid => [ 0, "User Id", "required", q/^\w+$/],
                _email => [ 10, "Email Address", "required|unique", q/^[\w\'\,\.\-]+\@[\w+-._]*.\w{2,3})$/],
                _password => [ 20, "(New) Password", "required|unique", q/^\w+$/],
                _validated => [ undef,"EmailValidated", "hidden", q/yes|no/],
                firstname => [ 40, "First Name", "required", q/^[\w+\.\,\s]+$/],
                lastname => [ 50, "Last Name", "required", q/^[\w+\.\,\s]+$/],

                                ## pgmset fields are not settable by the user.  hidden fields are not even visible
                accesslevel => [ 110, "Access Level", "pgmset", "set-to-default" ] ,
                secretfield => [ undef, undef, "hidden", q/^\d+$/ ] ,
                   }
            }, '/var/tmp/uschema.json'); ## if there is a second arg, store the schema, too.

  # global function
    Usermanager::Load( $hashptr_to_schema, $optional_filename_to_save_schema );

   get '/' => sub {
      my self= shift;
      my $sessionuid = $self->session('uid');  ## will be created and dragged around by UM on a webuser basis

      return $self->render(text => "various html stuff".UM::loginlogoutsnippet($uid)."more html stuff" )
   }

   get '/myfiles' => sub {
      my self= shift;
      UM::CheckUserValid( $self->session('uid') );  ## if possible, no arg required.  UM should grab $self->session('uid')
   }

   ...